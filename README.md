# Tor Go Web Scraper

Tor ağı (.onion servisleri) üzerinde yer alan web sitelerini anonim olarak taramak ve
CTI (Cyber Threat Intelligence) çalışmaları için veri toplamak amacıyla geliştirilmiş
Go tabanlı bir otomasyon aracıdır.

## Project Purpose

Dark web üzerindeki sızıntı siteleri, forumlar ve pazar yerleri gibi .onion servislerinin
manuel olarak izlenmesi ölçeklenebilir değildir. Bu proje, Tor ağı üzerinden anonim
şekilde çok sayıda hedefi otomatik olarak tarayarak içerik ve durum bilgisi toplamayı
amaçlamaktadır.

## Features

- Tor SOCKS5 proxy desteği (9050 / 9150 otomatik algılama)
- Go concurrency (worker pool) ile paralel tarama
- Çalışmayan (dead) sitelere karşı hata toleransı
- HTML içeriğinin offline ve adli incelemeye uygun şekilde kaydedilmesi
- Sayfa içi link çıkarımı
- Tor üzerinden tam sayfa ekran görüntüsü alma
- MHTML snapshot (sayfa arşivi)
- Tor IP doğrulama (check.torproject.org)
- Detaylı loglama (scan_report.log)

## Requirements

- Go 1.20 veya üzeri
- Yerel olarak çalışan Tor servisi
- Chromium veya Google Chrome

## Usage

```bash
go run main.go -f targets.yaml
