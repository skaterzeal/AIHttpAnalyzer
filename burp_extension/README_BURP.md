# Burp Suite Eklentisi Kurulumu

## Gereksinimler

- Burp Suite Professional veya Community Edition
- Jython 2.7+ jar dosyası

## Adımlar

1. **Jython İndirme**
   - https://www.jython.org/download.html adresinden `jython-standalone-2.7.x.jar` indirin.

2. **Burp Suite Ayarları**
   - Burp Suite'i açın.
   - `Extender` → `Options` sekmesine gidin.
   - `Python Environment` bölümünde `Location of Jython standalone JAR file` alanına indirdiğiniz jar dosyasının yolunu gösterin.

3. **Eklenti Yükleme**
   - `Extender` → `Extensions` sekmesine gidin.
   - `Add` butonuna tıklayın.
   - `Extension Type` olarak `Python` seçin.
   - `Extension file` alanından `HttpResponseAnalyzer.py` dosyasını seçin.
   - `Next` → `Close`.

4. **Yerel API Sunucusunu Başlatma**
   ```bash
   python -m src.api_server
   ```
   Bu sunucu varsayılan olarak `http://127.0.0.1:8765` adresinde çalışır.

5. **Kullanım**
   - Proxy veya Repeater üzerinden geçen response'lar otomatik olarak analiz edilir.
   - Bulgular `Comment` ve `Highlight` alanlarına yansıtılır.
