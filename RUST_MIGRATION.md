# HTTP Response Analyzer — Python → Rust Geçiş Yol Haritası

## Genel Strateji

Python orchestrator + AI katmanı her aşamada çalışır.
Rust modüller PyO3 ile `.so` olarak eklenir — Python API değişmez.
Faz 3'te Burp XML parser ve tüm extractors Rust'a taşınır.
AI (LLM) çağrıları Python'da kalabilir veya Faz 4'te reqwest ile taşınır.

---

## Faz 1: Rust Pattern Matchers (Ay 4–5)

Hedef: Python re → Rust regex + aho-corasick

Gerekli crate'ler:
  regex        = "1"
  aho-corasick = "1"    # stack trace / error signature çok pattern taraması
  serde_yaml   = "0.9"
  pyo3         = { version = "0.22", features = ["extension-module"] }

Hangi modüller:
  - stack_trace_extractor   → en çok regex döngüsü çalıştıran
  - error_extractor         → 30+ pattern, Aho-Corasick ile 20x kazanım
  - secret_extractor        → çoklu pattern

Performans hedefi: 10.000 response/dak  (Python: ~800/dak)

---

## Faz 2: Rust Burp XML Parser (Ay 5–6)

Hedef: lxml (Python) → quick-xml (Rust)

Gerekli crate'ler:
  quick-xml = "0.36"
  base64    = "0.22"

Avantaj: 100MB+ Burp export dosyalarında bellek kullanımı
Python lxml'e göre 3-5x daha az.

---

## Faz 3: Rust HTTP Response Parser (Ay 6–7)

Hedef: Python string split → httparse (Rust)

Gerekli crate'ler:
  httparse = "1"

Avantaj: RFC uyumlu, sıfır kopya (zero-copy) header parsing.

---

## Faz 4: Full Binary (Ay 8–10)

Cargo.toml bağımlılıkları:
  clap         = { version = "4", features = ["derive"] }
  tokio        = { version = "1", features = ["full"] }
  reqwest      = { version = "0.12", features = ["json"] }
  serde        = { version = "1", features = ["derive"] }
  serde_yaml   = "0.9"
  serde_json   = "1"
  rusqlite     = { version = "0.31", features = ["bundled"] }
  regex        = "1"
  aho-corasick = "1"
  quick-xml    = "0.36"
  httparse     = "1"
  base64       = "0.22"
  axum         = "0.7"   # Burp eklentisi için yerel API sunucu

CLI:
  http-response-analyzer analyze --burp export.xml --ai
  http-response-analyzer analyze --file response.http
  http-response-analyzer proxy --port 8082 --ai
  http-response-analyzer map --burp export.xml

Yerel API sunucu (Burp eklentisi için):
  axum ile /analyze endpoint'i — Python aiohttp'nin yerini alır.

Dağıtım:
  cargo build --release --target x86_64-unknown-linux-musl

---

## Benchmark Hedefleri

| Modül              | Python       | Rust Hedef      | Kazanım |
|--------------------|--------------|-----------------|---------|
| Pattern Matchers   | 800 resp/dak | 10.000 resp/dak | ~12x    |
| Burp XML Parser    | 5 MB/sn      | 25 MB/sn        | ~5x     |
| HTTP Parser        | 2.000 req/sn | 50.000 req/sn   | ~25x    |
| Error Scanner      | 1.000 pat/sn | 20.000 pat/sn   | ~20x    |

## Taşıma Öncelik Sırası

1. Pattern matchers (stack trace, error, secret) → en büyük kazanım
2. Burp XML parser                               → büyük dosya desteği
3. HTTP parser                                   → proxy modunda kritik
4. Yerel API sunucu                              → Burp eklentisi entegrasyonu
5. LLM çağrıları                                → Python'da kalabilir
