# TOR Scraper (Go)

Bu proje, yerel **Tor SOCKS5 proxy** üzerinden trafiği yönlendirerek `targets.yaml` içindeki `.onion` URL’lerini (ve/veya clearnet doğrulama URL’lerini) ziyaret eder, **HTML**’i kaydeder ve (opsiyonel) **screenshot** alır.

> Bu ödevin amacı, CTI süreçlerinde “Collection/Automation” yetkinliği kazandırmak ve Tor üzerinden anonim veri toplama otomasyonudur.

## 1) Klasör Yapısı

```
tor_scraper_project/
  go.mod
  main.go
  targets.yaml
```

Çıktılar çalıştırma anında `out/run_YYYYmmdd_HHMMSS/` içine yazılır:

```
out/run_.../
  html/                # kaydedilen HTML
  screenshots/         # (opsiyonel) PNG ekran görüntüleri
  scan_report.log      # insan-okur log
  scan_report.jsonl    # satır satır JSON (rapor/analiz için)
```

## 2) targets.yaml formatı

Program “**bir satır = bir URL**” mantığında okur. Ayrıca YAML listesi gibi `- url` formatını da kabul eder.

Örnek:

```txt
# Yorum satırları OK
- http://SENIN_ONION.onion/
https://check.torproject.org/
```

İpucu: Eğer elindeki dosyada `Site Linki: http://....onion/` gibi satırlar varsa, program satırın içinden `.onion` URL’yi regex ile çıkarır.

## 3) Tor’u çalıştırma

- **Tor Browser** kullanıyorsan genelde SOCKS portu `9150` olur.
- **Tor service / expert bundle** kullanıyorsan genelde SOCKS portu `9050` olur.

Programı buna göre çalıştır:

```bash
go run . -targets targets.yaml -proxy 127.0.0.1:9150
```

## 4) Çalıştırma

Basit:

```bash
go run . -targets targets.yaml
```

Parametreler:

- `-targets` hedef dosya yolu
- `-out` çıktı kök dizini (default: out)
- `-proxy` Tor SOCKS5 (default: 127.0.0.1:9050)
- `-timeout` istek timeout (default: 60s)
- `-concurrency` eşzamanlı worker sayısı (default: 3)
- `-screenshot` true/false (default: true)
- `-chrome` chrome.exe yolu (boşsa otomatik arar)
- `-insecure` TLS doğrulamasını kapatır (default: true; onion tarafında self-signed sık olabiliyor)
- `-max-bytes` HTML kaydı için üst limit (default: 3MB)

## 5) Screenshot notu (Windows)

Screenshot alma kısmı **headless Chrome/Edge** çağırır. Chrome bulunamazsa warning basar ve HTML toplamaya devam eder.

Eğer `.onion` ekran görüntüsü kısmında DNS sorunları görürsen:
- `-screenshot=false` ile kapatıp ödevin HTML + log kısmını garantiye al,
- veya Tor Browser üzerinden manuel screenshot al (rapora eklemek için),
- veya daha gelişmiş yöntem olarak `chromedp` entegrasyonu yap.

## 6) Legal/Ethical not

Bu araç sadece **yetkili olduğun** hedefler ve **etik/yasal sınırlar** içinde kullanılmalıdır. Hesap açma, login, içerik indirme/satın alma vb. etkileşimleri otomatikleştirmeyi eklemedim.
