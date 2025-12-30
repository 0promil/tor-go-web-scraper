package main

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"golang.org/x/net/proxy"
)

const (
	torProxy1 = "127.0.0.1:9050"
	torProxy2 = "127.0.0.1:9150"
	timeout   = 25 * time.Second
	workers   = 5
)

var activeTorProxy string

func main() {
	filePath := flag.String("f", "", "targets.yaml")
	flag.Parse()
	if *filePath == "" {
		fmt.Println("Kullanım: tor_scraper -f targets.yaml")
		return
	}
	setupLogging()
	activeTorProxy = ensureTorAvailable()
	os.MkdirAll("output", 0755)
	targets := readTargets(*filePath)
	client := torHTTPClient(activeTorProxy)
	verifyTorIP(client)
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(client, jobs, &wg)
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	fmt.Println("Tarama tamamlandı.")
}
func setupLogging() {
	logFile, _ := os.OpenFile(
		"scan_report.log",
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	log.SetOutput(logFile)
}
func ensureTorAvailable() string {
	if checkPort(torProxy1) {
		log.Println("[INFO] Tor aktif:", torProxy1)
		return torProxy1
	}
	if checkPort(torProxy2) {
		log.Println("[INFO] Tor aktif:", torProxy2)
		return torProxy2
	}
	log.Fatal("[FATAL] Tor SOCKS5 bulunamadı")
	return ""
}
func checkPort(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
func torHTTPClient(proxyAddr string) *http.Client {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatal("SOCKS5 dialer oluşturulamadı")
	}
	return &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   timeout,
	}
}
func verifyTorIP(client *http.Client) {
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		log.Println("[TOR] IP doğrulama başarısız")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Println("[TOR] check.torproject.org:", string(body))
	fmt.Println("[TOR] check.torproject.org:", string(body))
}
func readTargets(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("targets.yaml açılamadı")
	}
	defer file.Close()
	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		targets = append(targets, line)
	}
	return targets
}
func worker(client *http.Client, jobs <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range jobs {
		scanTarget(client, target)
	}
}
func scanTarget(client *http.Client, target string) {
	start := time.Now()
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent",
		"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERR ] %s -> TIMEOUT\n", target)
		return
	}
	defer resp.Body.Close()
	body, err := readResponseBody(resp)
	if err != nil {
		log.Printf("[ERR ] %s -> READ ERROR\n", target)
		return
	}
	title := extractTitle(string(body))
	outDir := buildOutputDir(target, title)
	os.MkdirAll(outDir, 0755)
	safeHTML := sanitizeHTML(string(body))
	os.WriteFile(
		filepath.Join(outDir, "site_data.html"),
		[]byte(safeHTML),
		0644,
	)
	links := extractLinks(string(body))
	os.WriteFile(
		filepath.Join(outDir, "links.txt"),
		[]byte(strings.Join(links, "\n")),
		0644,
	)
	if err := takeScreenshotTor(target, outDir); err != nil {
		log.Printf("[ERR ] %s -> SCREENSHOT FAILED\n", target)
	}
	elapsed := time.Since(start)
	log.Printf("[INFO] %s -> %d (%v)\n", target, resp.StatusCode, elapsed)
	fmt.Println("[OK ]", target)
}
func readResponseBody(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body

	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	case "deflate":
		reader = flate.NewReader(resp.Body)
		defer reader.(io.ReadCloser).Close()
	}
	return io.ReadAll(reader)
}

func sanitizeHTML(html string) string {
	notice := `<!--
OFFLINE
-->`

	reBase := regexp.MustCompile(`(?i)<base[^>]*>`)
	html = reBase.ReplaceAllString(html, "")

	reHref := regexp.MustCompile(`(?i)href=["'][^"']+["']`)
	html = reHref.ReplaceAllString(html, `href="#"`)

	reSrc := regexp.MustCompile(`(?i)src=["'][^"']+["']`)
	html = reSrc.ReplaceAllString(html, `src=""`)

	return notice + "\n" + html
}
func extractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	m := re.FindStringSubmatch(html)
	if len(m) > 1 {
		t := strings.TrimSpace(m[1])
		t = regexp.MustCompile(`[^a-zA-Z0-9 _\-]`).ReplaceAllString(t, "")
		return strings.ReplaceAll(t, " ", "_")
	}
	return "unknown_title"
}
func extractLinks(html string) []string {
	re := regexp.MustCompile(`href=["'](http[^"']+)`)
	matches := re.FindAllStringSubmatch(html, -1)
	seen := make(map[string]bool)
	var links []string
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			links = append(links, m[1])
		}
	}
	return links
}
func buildOutputDir(rawURL, title string) string {
	u, _ := url.Parse(rawURL)
	site := strings.ReplaceAll(u.Host, ".onion", "")
	ts := time.Now().Format("2006-01-02_15-04-05")

	hash := sha256.Sum256([]byte(rawURL))
	short := hex.EncodeToString(hash[:])[:6]

	return fmt.Sprintf("output/%s_%s_%s_%s", title, ts, site, short)
}
func takeScreenshotTor(target, outDir string) error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer("socks5://"+activeTorProxy),
		chromedp.Headless,
		chromedp.DisableGPU,
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	var screenshot []byte
	var mhtml string
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1920, 1080),
		chromedp.Navigate(target),
		chromedp.Sleep(5*time.Second),
		chromedp.FullScreenshot(&screenshot, 90),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			mhtml, err = page.CaptureSnapshot().Do(ctx)
			return err
		}),
	)
	if err != nil {
		return err
	}
	os.WriteFile(filepath.Join(outDir, "screenshot.png"), screenshot, 0644)
	os.WriteFile(filepath.Join(outDir, "site_snapshot.mhtml"), []byte(mhtml), 0644)
	return nil
}
