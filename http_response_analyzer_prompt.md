# AI-Destekli HTTP Response Analyzer — Proje Build Promptu

## GÖREV

Aşağıda mimarisi, modülleri ve gereksinimleri tam olarak tanımlanmış olan
**AI-Destekli HTTP Response Analyzer** adlı profesyonel bir pentest aracını
Python ile implement et. Her modülü ayrı dosya olarak yaz, tüm bağımlılıkları
kur, CLI'yi ve Burp Suite eklenti uyumunu çalışır hale getir, temel testleri
ekle.

Ek olarak: Python implementasyonu tamamlandıktan sonra Rust'a geçiş için
`RUST_MIGRATION.md` dosyasını da oluştur.

---

## PROJE YAPISI

```
http_response_analyzer/
├── src/
│   ├── __init__.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── burp_importer.py
│   │   ├── raw_http_parser.py
│   │   ├── proxy_listener.py
│   │   └── file_loader.py
│   ├── extractors/
│   │   ├── __init__.py
│   │   ├── endpoint_extractor.py
│   │   ├── stack_trace_extractor.py
│   │   ├── version_extractor.py
│   │   ├── secret_extractor.py
│   │   ├── error_extractor.py
│   │   └── technology_fingerprinter.py
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── response_analyzer.py
│   │   ├── exploit_suggester.py
│   │   ├── context_builder.py
│   │   └── batch_processor.py
│   ├── correlation/
│   │   ├── __init__.py
│   │   ├── pattern_correlator.py
│   │   ├── session_tracker.py
│   │   └── attack_surface_mapper.py
│   ├── output/
│   │   ├── __init__.py
│   │   ├── json_exporter.py
│   │   ├── markdown_reporter.py
│   │   ├── burp_annotation.py
│   │   ├── sarif_exporter.py
│   │   └── sqlite_store.py
│   └── core/
│       ├── __init__.py
│       ├── engine.py
│       └── models.py
├── burp_extension/
│   ├── HttpResponseAnalyzer.py   # Burp Suite Jython eklentisi
│   └── README_BURP.md
├── data/
│   ├── patterns/
│   │   ├── stack_traces.yaml
│   │   ├── version_patterns.yaml
│   │   ├── error_signatures.yaml
│   │   └── technology_fingerprints.yaml
│   └── wordlists/
│       └── common_api_paths.txt
├── tests/
│   ├── fixtures/
│   │   ├── sample_responses/
│   │   │   ├── django_debug.http
│   │   │   ├── spring_actuator.http
│   │   │   ├── laravel_error.http
│   │   │   └── graphql_introspection.http
│   │   └── burp_export.xml
│   ├── test_endpoint_extractor.py
│   ├── test_stack_trace_extractor.py
│   ├── test_version_extractor.py
│   └── test_response_analyzer.py
├── configs/
│   └── default.yaml
├── main.py
├── pyproject.toml
├── RUST_MIGRATION.md
└── README.md
```

---

## BAĞIMLILIKLAR

```toml
[project]
name = "http-response-analyzer"
version = "0.1.0"
requires-python = ">=3.11"

dependencies = [
    "httpx>=0.27.0",
    "aiohttp>=3.9.0",
    "asyncio",
    "pyyaml>=6.0",
    "aiosqlite>=0.20.0",
    "rich>=13.7.0",
    "typer>=0.12.0",
    "pydantic>=2.6.0",
    "openai>=1.30.0",
    "ollama>=0.2.0",
    "beautifulsoup4>=4.12.0",
    "lxml>=5.2.0",
    "mitmproxy>=10.3.0",
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
]
```

---

## CLI ARAYÜZÜ

`main.py` içinde `typer` ile aşağıdaki komutları implement et:

```
# Tek response dosyası analizi
python main.py analyze --file response.http

# Burp Suite XML export analizi (toplu)
python main.py analyze --burp burp_export.xml

# Dizindeki tüm .http dosyaları
python main.py analyze --dir ./responses/

# Canlı proxy modu (mitmproxy entegrasyonu)
python main.py proxy --port 8082 --ai

# URL'e istek at ve yanıtı analiz et
python main.py request --url https://example.com/api/v1/users \
    --method GET --header "Authorization: Bearer token123"

# AI sorgulama modu — belirli bir soruyu yanıtla
python main.py ask --file response.http \
    --question "Bu response'ta IDOR zafiyeti var mı?"

# Tüm response'ları birleştirip saldırı yüzeyi haritası çıkar
python main.py map --burp burp_export.xml --output attack_surface.md

# Çıktı formatları
python main.py analyze --burp burp_export.xml \
    --output markdown --output-file report.md

python main.py analyze --burp burp_export.xml \
    --output sarif --output-file findings.sarif
```

**CLI parametreleri:**

| Parametre | Tip | Varsayılan | Açıklama |
|---|---|---|---|
| `--file` | Path | — | Tek .http dosyası |
| `--burp` | Path | — | Burp Suite XML export |
| `--dir` | Path | — | Dizindeki tüm .http dosyaları |
| `--url` | str | — | Doğrudan istek URL'i |
| `--method` | str | GET | HTTP metodu |
| `--header` | list[str] | — | Ekstra headerlar |
| `--ai` | flag | False | AI analizini etkinleştir |
| `--llm-provider` | enum | ollama | ollama / openai / anthropic |
| `--api-key` | str | — | LLM API anahtarı |
| `--question` | str | — | AI'a özel soru |
| `--min-severity` | enum | low | info/low/medium/high/critical |
| `--output` | enum | json | json/markdown/sarif/burp |
| `--output-file` | Path | — | Çıktı dosyası |
| `--port` | int | 8082 | Proxy dinleme portu |
| `--no-cache` | flag | False | Cache devre dışı |
| `--verbose` | flag | False | Ayrıntılı log |
| `--config` | Path | configs/default.yaml | Özel config |
| `--batch-size` | int | 10 | AI toplu işlem boyutu |

---

## MODÜL DETAYLARI

### 1. `src/core/models.py` — Veri modelleri

```python
from pydantic import BaseModel
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class FindingType(str, Enum):
    ENDPOINT_DISCOVERED   = "endpoint_discovered"
    STACK_TRACE           = "stack_trace"
    VERSION_DISCLOSURE    = "version_disclosure"
    SECRET_EXPOSURE       = "secret_exposure"
    ERROR_MESSAGE         = "error_message"
    DEBUG_INFO            = "debug_info"
    TECHNOLOGY_DETECTED   = "technology_detected"
    MISCONFIG_DETECTED    = "misconfig_detected"
    EXPLOIT_OPPORTUNITY   = "exploit_opportunity"

class HTTPRequest(BaseModel):
    method: str
    url: str
    path: str
    headers: dict[str, str]
    body: str | None
    timestamp: datetime | None

class HTTPResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str | None
    size_bytes: int
    response_time_ms: float | None
    request: HTTPRequest | None
    source: str                    # "burp", "file", "proxy", "direct"

class ExtractedFinding(BaseModel):
    id: str
    finding_type: FindingType
    severity: Severity
    title: str
    detail: str
    evidence: str                  # response'tan alınan snippet
    location: str                  # header adı / body XPath / satır no
    response_id: str
    confidence: float              # 0.0 – 1.0

class AIAnalysisResult(BaseModel):
    response_id: str
    summary: str                   # 2-3 cümle genel değerlendirme
    exploitable_findings: list[str]
    recommended_tests: list[str]   # "SQLi dene", "IDOR test et" vb.
    risk_level: Severity
    reasoning: str
    raw_llm_output: str

class AnalyzedResponse(BaseModel):
    response_id: str
    response: HTTPResponse
    findings: list[ExtractedFinding]
    ai_analysis: AIAnalysisResult | None
    endpoints_found: list[str]
    technologies: list[str]
    analyzed_at: datetime

class AttackSurfaceMap(BaseModel):
    target: str
    total_responses: int
    unique_endpoints: list[str]
    technologies: dict[str, str]   # {"framework": "Django 3.2", ...}
    critical_findings: list[ExtractedFinding]
    ai_summary: str
    generated_at: datetime
```

---

### 2. `configs/default.yaml`

```yaml
analysis:
  extract_endpoints: true
  extract_stack_traces: true
  extract_versions: true
  extract_secrets: true
  extract_errors: true
  fingerprint_technology: true

ai:
  enabled: false
  provider: ollama
  model: llama3.2
  temperature: 0.2
  max_tokens: 2000
  batch_size: 10              # kaç response'u tek seferde analiz et
  confidence_threshold: 0.6

output:
  format: json
  min_severity: low
  include_evidence: true
  max_evidence_length: 500    # snippet maksimum karakter

proxy:
  port: 8082
  intercept_responses: true
  filter_content_types:
    - "application/json"
    - "text/html"
    - "text/plain"
    - "application/xml"

cache:
  enabled: true
  ttl_hours: 48
```

---

### 3. `data/patterns/stack_traces.yaml`

```yaml
patterns:
  - id: python_traceback
    name: Python Traceback
    severity: high
    regex: "Traceback \\(most recent call last\\):[\\s\\S]*?(?:Error|Exception):.+"
    frameworks: ["Django", "Flask", "FastAPI", "Python"]
    extract_fields:
      - "file_paths"
      - "line_numbers"
      - "exception_type"
      - "exception_message"

  - id: java_stacktrace
    name: Java Stack Trace
    severity: high
    regex: "(?:java|com|org|net)\\.[a-zA-Z.]+Exception.+(?:\\n\\s+at .+)+"
    frameworks: ["Spring", "Tomcat", "Java EE"]
    extract_fields:
      - "exception_class"
      - "package_structure"
      - "line_numbers"

  - id: php_error
    name: PHP Error / Warning
    severity: high
    regex: "(?:Fatal error|Warning|Notice|Parse error):.+in /.+\\.php on line \\d+"
    frameworks: ["Laravel", "Symfony", "WordPress", "PHP"]
    extract_fields:
      - "file_path"
      - "line_number"
      - "error_type"

  - id: dotnet_exception
    name: .NET Exception
    severity: high
    regex: "System\\.[A-Za-z.]+Exception:.+(?:\\n   at .+)+"
    frameworks: [".NET", "ASP.NET", "C#"]
    extract_fields:
      - "exception_type"
      - "namespace_info"

  - id: ruby_stacktrace
    name: Ruby Stack Trace
    severity: high
    regex: "[A-Za-z:]+Error.+(?:\\n\\s+from .+:\\d+:in .+)+"
    frameworks: ["Rails", "Sinatra", "Ruby"]
    extract_fields:
      - "error_type"
      - "file_paths"

  - id: node_stacktrace
    name: Node.js Stack Trace
    severity: high
    regex: "(?:Error|TypeError|ReferenceError):.+(?:\\n\\s+at .+)+"
    frameworks: ["Express", "Node.js", "Next.js"]
    extract_fields:
      - "error_type"
      - "file_paths"
      - "line_numbers"
```

**`data/patterns/version_patterns.yaml`:**
```yaml
patterns:
  # HTTP Headers
  - id: server_header
    name: Server Header Version
    severity: low
    source: header
    header_name: "server"
    regex: "(?:Apache|nginx|IIS|LiteSpeed|Caddy|gunicorn)[/\\s]([0-9.]+)"
    extract: "version"

  - id: x_powered_by
    name: X-Powered-By Header
    severity: medium
    source: header
    header_name: "x-powered-by"
    regex: "(?:PHP|ASP\\.NET|Express)[/\\s]([0-9.]+)"
    extract: "version"

  - id: x_aspnet_version
    name: ASP.NET Version Header
    severity: medium
    source: header
    header_name: "x-aspnet-version"
    regex: "([0-9.]+)"
    extract: "version"

  # Response Body
  - id: django_version_body
    name: Django Version in Body
    severity: high
    source: body
    regex: "Django[/\\s]([0-9.]+)"
    context: "debug_page"

  - id: spring_version
    name: Spring Boot Version
    severity: medium
    source: body
    regex: "Spring(?:Boot|Framework)[/\\s]([0-9.]+)"

  - id: laravel_version
    name: Laravel Version
    severity: medium
    source: body
    regex: "laravel[/\\s]v?([0-9.]+)"

  - id: wordpress_version
    name: WordPress Version
    severity: medium
    source: body
    regex: "WordPress ([0-9.]+)"

  - id: jquery_version
    name: jQuery Version
    severity: info
    source: body
    regex: "jquery[/\\s-]([0-9.]+)(?:\\.min)?\\.js"

  - id: react_version
    name: React Version
    severity: info
    source: body
    regex: "react(?:-dom)?[/\\s@]([0-9.]+)"
```

**`data/patterns/error_signatures.yaml`:**
```yaml
signatures:
  - id: sql_error_mysql
    name: MySQL SQL Error
    severity: high
    patterns:
      - "You have an error in your SQL syntax"
      - "mysql_fetch_array()"
      - "MySQL server version for the right syntax"
      - "supplied argument is not a valid MySQL"
    implication: "SQL injection potansiyel — hata mesajı sözdizimi bilgisi veriyor"

  - id: sql_error_mssql
    name: MSSQL SQL Error
    severity: high
    patterns:
      - "Unclosed quotation mark after the character string"
      - "Incorrect syntax near"
      - "Microsoft OLE DB Provider for SQL Server"
      - "SqlException"
    implication: "MSSQL hata mesajı — SQL injection araştır"

  - id: sql_error_oracle
    name: Oracle SQL Error
    severity: high
    patterns:
      - "ORA-[0-9]{5}"
      - "Oracle error"
      - "PLS-[0-9]{5}"
    implication: "Oracle DB hata kodu — SQL injection araştır"

  - id: sql_error_postgres
    name: PostgreSQL Error
    severity: high
    patterns:
      - "pg_query()"
      - "PostgreSQL query failed"
      - "ERROR:  syntax error at or near"
      - "PSQLException"
    implication: "PostgreSQL hata mesajı"

  - id: path_disclosure
    name: Full Path Disclosure
    severity: medium
    patterns:
      - "/var/www/html/"
      - "/home/[a-z]+/public_html/"
      - "C:\\\\inetpub\\\\wwwroot\\\\"
      - "/usr/local/apache"
      - "/opt/tomcat"
    implication: "Sunucu dosya sistemi yolu ifşa — hedefleme için kullanılabilir"

  - id: debug_mode_active
    name: Debug Mode Active
    severity: high
    patterns:
      - "DEBUG = True"
      - "debug: true"
      - "APP_DEBUG=true"
      - "FLASK_DEBUG=1"
      - "development mode"
    implication: "Uygulama debug modunda — detaylı hata bilgisi ifşa"

  - id: spring_actuator
    name: Spring Boot Actuator Exposed
    severity: high
    patterns:
      - "/actuator/env"
      - "/actuator/dump"
      - "/actuator/trace"
      - "\"activeProfiles\":"
      - "\"systemEnvironment\":"
    implication: "Spring Actuator endpoint'leri açık — env değişkenleri, heap dump erişilebilir"

  - id: graphql_introspection
    name: GraphQL Introspection Enabled
    severity: medium
    patterns:
      - "\"__schema\":"
      - "\"__types\":"
      - "\"queryType\":"
    implication: "GraphQL introspection açık — tüm şema keşfedilebilir"

  - id: swagger_exposed
    name: Swagger / OpenAPI Exposed
    severity: medium
    patterns:
      - "\"swagger\": \"2.0\""
      - "\"openapi\": \"3."
      - "swaggerUi.presets"
      - "SwaggerUIBundle("
    implication: "API dokümantasyonu açık — tüm endpoint'ler ve parametreler görünür"

  - id: aws_metadata
    name: AWS Metadata Leak
    severity: critical
    patterns:
      - "169.254.169.254"
      - "ec2metadata"
      - "\"AccessKeyId\":"
      - "\"SecretAccessKey\":"
    implication: "AWS meta-data servisine erişim veya credential ifşası"
```

**`data/patterns/technology_fingerprints.yaml`:**
```yaml
fingerprints:
  - name: Django
    indicators:
      headers:
        - name: "x-frame-options"
          value: "SAMEORIGIN"
        - name: "set-cookie"
          pattern: "csrftoken="
      body:
        - "django"
        - "{% csrf_token %}"
        - "CSRF verification failed"
    version_from: "body"

  - name: Laravel
    indicators:
      headers:
        - name: "set-cookie"
          pattern: "laravel_session="
      body:
        - "laravel"
        - "Illuminate\\"
        - "LARAVEL_SESSION"
    version_from: "body"

  - name: Spring Boot
    indicators:
      headers:
        - name: "x-application-context"
          pattern: ".*"
      body:
        - "\"timestamp\":"
        - "\"status\":"
        - "\"error\":"
        - "Whitelabel Error Page"
    version_from: "actuator"

  - name: Express.js
    indicators:
      headers:
        - name: "x-powered-by"
          value: "Express"
      body:
        - "Cannot GET"
        - "Cannot POST"
    version_from: "header"

  - name: WordPress
    indicators:
      headers: []
      body:
        - "wp-content"
        - "wp-includes"
        - "wordpress"
    version_from: "body"

  - name: ASP.NET
    indicators:
      headers:
        - name: "x-powered-by"
          pattern: "ASP\\.NET"
        - name: "x-aspnet-version"
          pattern: ".*"
      body:
        - "__VIEWSTATE"
        - "__EVENTVALIDATION"
    version_from: "header"
```

---

### 4. `src/ingestion/burp_importer.py`

```python
from lxml import etree

class BurpImporter:
    def parse(self, xml_path: str) -> list[HTTPResponse]:
        """
        Burp Suite XML export dosyasını parse et.

        Burp XML formatı:
        <items burpVersion="...">
          <item>
            <time>...</time>
            <url>...</url>
            <host>...</host>
            <port>...</port>
            <protocol>...</protocol>
            <method>...</method>
            <path>...</path>
            <request base64="true">...</request>
            <response base64="true">...</response>
            <status>200</status>
            <responselength>1234</responselength>
            <mimetype>JSON</mimetype>
          </item>
        </items>
        """
        tree  = etree.parse(xml_path)
        items = tree.findall(".//item")
        responses = []

        for item in items:
            try:
                responses.append(self._parse_item(item))
            except Exception:
                continue  # parse edilemeyen item'ları atla

        return responses

    def _parse_item(self, item) -> HTTPResponse:
        import base64

        # Request
        req_raw = item.findtext("request") or ""
        req_b64 = item.find("request")
        if req_b64 is not None and req_b64.get("base64") == "true":
            req_raw = base64.b64decode(req_raw).decode("utf-8", errors="ignore")

        # Response
        resp_raw = item.findtext("response") or ""
        resp_el  = item.find("response")
        if resp_el is not None and resp_el.get("base64") == "true":
            resp_raw = base64.b64decode(resp_raw).decode("utf-8", errors="ignore")

        return self._parse_raw_http(
            request_raw  = req_raw,
            response_raw = resp_raw,
            url          = item.findtext("url") or "",
            status_code  = int(item.findtext("status") or 0),
            source       = "burp",
        )

    def _parse_raw_http(
        self,
        request_raw: str,
        response_raw: str,
        url: str,
        status_code: int,
        source: str,
    ) -> HTTPResponse:
        """Ham HTTP metin bloğunu HTTPResponse modeline dönüştür."""
        # Header / body ayır
        if "\r\n\r\n" in response_raw:
            header_block, body = response_raw.split("\r\n\r\n", 1)
        elif "\n\n" in response_raw:
            header_block, body = response_raw.split("\n\n", 1)
        else:
            header_block, body = response_raw, ""

        # Header'ları parse et
        headers = {}
        for line in header_block.split("\n")[1:]:  # ilk satır status line
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        return HTTPResponse(
            status_code  = status_code,
            headers      = headers,
            body         = body,
            content_type = headers.get("content-type"),
            size_bytes   = len(body.encode("utf-8", errors="ignore")),
            response_time_ms = None,
            request      = self._parse_request(request_raw, url),
            source       = source,
        )
```

---

### 5. `src/ingestion/proxy_listener.py`

mitmproxy ile canlı trafik yakalama:

```python
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options

class ResponseCapture:
    def __init__(self, engine, ai_enabled: bool = False):
        self.engine     = engine
        self.ai_enabled = ai_enabled
        self.queue: asyncio.Queue = asyncio.Queue()

    def response(self, flow: http.HTTPFlow):
        """mitmproxy her response aldığında bu method çağrılır."""
        resp = HTTPResponse(
            status_code      = flow.response.status_code,
            headers          = dict(flow.response.headers),
            body             = flow.response.text or "",
            content_type     = flow.response.headers.get("content-type"),
            size_bytes       = len(flow.response.content),
            response_time_ms = None,
            request          = HTTPRequest(
                method  = flow.request.method,
                url     = flow.request.pretty_url,
                path    = flow.request.path,
                headers = dict(flow.request.headers),
                body    = flow.request.text,
            ),
            source = "proxy",
        )
        asyncio.create_task(self._analyze_and_annotate(flow, resp))

    async def _analyze_and_annotate(self, flow, resp: HTTPResponse):
        result = await self.engine.analyze_single(resp)
        # Burp benzeri notasyon: bulgu varsa flow'u işaretle
        if result.findings:
            severity_counts = {}
            for f in result.findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            flow.comment = f"[AI Analyzer] {len(result.findings)} finding: {severity_counts}"
```

---

### 6. `src/extractors/endpoint_extractor.py`

```python
class EndpointExtractor:
    # API endpoint kalıpları
    PATTERNS = [
        # JSON anahtarları: "url", "endpoint", "href", "action" vb.
        re.compile(r'"(?:url|endpoint|href|action|src|link|path|api_url|base_url)"\s*:\s*"(/[^"]{2,})"'),
        # HTML form action'ları
        re.compile(r'action=["\']([^"\']+)["\']'),
        # HTML link'ler
        re.compile(r'href=["\'](/[a-zA-Z0-9/_\-?.=&%#]+)["\']'),
        # JS fetch/axios çağrıları
        re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](/[^'"]+)'''),
        # REST path'leri: /api/v1/... , /v2/... vb.
        re.compile(r'"(/(?:api|v\d+|rest|graphql|gql|rpc)/[a-zA-Z0-9/_\-?.=&%#]+)"'),
        # Relative URL'ler (/users/123)
        re.compile(r'"(/[a-zA-Z][a-zA-Z0-9/_\-]{3,}(?:\.[a-zA-Z]{2,4})?)"'),
    ]

    # Çok genel veya anlamsız path'leri filtrele
    BLOCKLIST = {"/", "//", "/.", "/*", "/null", "/undefined",
                 "/true", "/false", "/0", "/1"}

    def extract(self, response: HTTPResponse) -> list[str]:
        """
        Response body ve Location headerından endpoint'leri çıkar.
        """
        found = set()
        body  = response.body

        for pat in self.PATTERNS:
            for m in pat.finditer(body):
                path = m.group(1)
                if self._is_valid_path(path):
                    found.add(path)

        # Location header
        loc = response.headers.get("location", "")
        if loc.startswith("/"):
            found.add(loc)

        # Content-Location header
        cl = response.headers.get("content-location", "")
        if cl.startswith("/"):
            found.add(cl)

        return sorted(found)

    def _is_valid_path(self, path: str) -> bool:
        if path in self.BLOCKLIST:
            return False
        if len(path) < 2 or len(path) > 200:
            return False
        # Sadece path karakterleri içermeli
        if re.search(r'[<>{}|\\^`\[\]\s]', path):
            return False
        return True
```

---

### 7. `src/extractors/stack_trace_extractor.py`

```python
class StackTraceExtractor:
    def __init__(self):
        self.patterns = yaml.safe_load(
            open("data/patterns/stack_traces.yaml")
        )["patterns"]

    def extract(self, response: HTTPResponse) -> list[ExtractedFinding]:
        findings = []
        body     = response.body

        for pat in self.patterns:
            m = re.search(pat["regex"], body, re.MULTILINE | re.DOTALL)
            if not m:
                continue

            raw_trace = m.group(0)
            fields    = self._extract_fields(raw_trace, pat.get("extract_fields", []))

            findings.append(ExtractedFinding(
                id           = str(uuid.uuid4()),
                finding_type = FindingType.STACK_TRACE,
                severity     = Severity(pat["severity"]),
                title        = pat["name"],
                detail       = (
                    f"Framework: {', '.join(pat.get('frameworks', []))}\n"
                    f"Çıkarılan bilgiler: {fields}"
                ),
                evidence     = raw_trace[:500],
                location     = "body",
                response_id  = response.source,
                confidence   = 0.95,
            ))

        return findings

    def _extract_fields(self, trace: str, field_names: list[str]) -> dict:
        fields = {}
        if "file_paths" in field_names:
            fields["file_paths"] = re.findall(
                r'(?:/[a-zA-Z0-9_\-./]+\.(?:py|php|java|rb|js|ts|cs))', trace
            )
        if "line_numbers" in field_names:
            fields["line_numbers"] = re.findall(r'line (\d+)', trace)
        if "exception_type" in field_names:
            m = re.search(r'([A-Za-z]+(?:Error|Exception|Warning))', trace)
            if m:
                fields["exception_type"] = m.group(1)
        return fields
```

---

### 8. `src/extractors/version_extractor.py`

```python
class VersionExtractor:
    def __init__(self):
        self.patterns = yaml.safe_load(
            open("data/patterns/version_patterns.yaml")
        )["patterns"]

    def extract(self, response: HTTPResponse) -> list[ExtractedFinding]:
        findings = []

        for pat in self.patterns:
            source = pat["source"]
            target_text = ""

            if source == "header":
                target_text = response.headers.get(
                    pat.get("header_name", ""), ""
                )
            elif source == "body":
                target_text = response.body

            m = re.search(pat["regex"], target_text, re.IGNORECASE)
            if not m:
                continue

            version = m.group(1) if m.lastindex else m.group(0)

            findings.append(ExtractedFinding(
                id           = str(uuid.uuid4()),
                finding_type = FindingType.VERSION_DISCLOSURE,
                severity     = Severity(pat["severity"]),
                title        = pat["name"],
                detail       = f"Tespit edilen versiyon: {version}",
                evidence     = m.group(0),
                location     = f"{source}:{pat.get('header_name', 'body')}",
                response_id  = "",
                confidence   = 0.90,
            ))

        return findings
```

---

### 9. `src/extractors/technology_fingerprinter.py`

```python
class TechnologyFingerprinter:
    def __init__(self):
        self.fingerprints = yaml.safe_load(
            open("data/patterns/technology_fingerprints.yaml")
        )["fingerprints"]

    def detect(self, response: HTTPResponse) -> list[str]:
        """
        Response header ve body'den kullanılan teknoloji stack'ini tespit et.
        Döndür: ["Django", "PostgreSQL", "Nginx 1.24"] gibi liste.
        """
        detected = []

        for fp in self.fingerprints:
            score = 0
            total = 0

            # Header indikatörleri
            for ind in fp.get("indicators", {}).get("headers", []):
                total += 1
                val = response.headers.get(ind["name"].lower(), "")
                if "value" in ind and val.lower() == ind["value"].lower():
                    score += 1
                elif "pattern" in ind and re.search(ind["pattern"], val, re.I):
                    score += 1

            # Body indikatörleri
            for kw in fp.get("indicators", {}).get("body", []):
                total += 1
                if kw.lower() in response.body.lower():
                    score += 1

            # Eşleşme eşiği: indikatörlerin en az %40'ı
            if total > 0 and score / total >= 0.4:
                detected.append(fp["name"])

        return detected
```

---

### 10. `src/extractors/secret_extractor.py`

```python
# Yaygın sır kalıpları — JS Secret Hunter'a kıyasla response'a özgü
SECRET_PATTERNS = {
    "api_key_json":     re.compile(r'"(?:api_?key|apikey|access_?key)"\s*:\s*"([^"]{16,})"'),
    "token_json":       re.compile(r'"(?:token|access_token|auth_token)"\s*:\s*"([^"]{16,})"'),
    "password_json":    re.compile(r'"(?:password|passwd|pwd|secret)"\s*:\s*"([^"]{4,})"'),
    "aws_key":          re.compile(r'AKIA[0-9A-Z]{16}'),
    "jwt":              re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'),
    "private_key":      re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "db_url":           re.compile(r'(?:mysql|postgresql|mongodb|redis)://[^\s\'"<>]+'),
    "internal_ip":      re.compile(r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+'),
    "email_internal":   re.compile(r'[a-zA-Z0-9._%+-]+@(?:internal|corp|local|intranet)\.[a-zA-Z]+'),
}

class SecretExtractor:
    def extract(self, response: HTTPResponse) -> list[ExtractedFinding]:
        findings = []
        body = response.body

        for name, pat in SECRET_PATTERNS.items():
            for m in pat.finditer(body):
                value = m.group(1) if m.lastindex else m.group(0)
                # Kısa veya düşük entropili değerleri atla
                if len(value) < 8:
                    continue

                findings.append(ExtractedFinding(
                    id           = str(uuid.uuid4()),
                    finding_type = FindingType.SECRET_EXPOSURE,
                    severity     = Severity.HIGH,
                    title        = f"Response İçinde Sır: {name}",
                    detail       = f"Response body'de {name} deseni bulundu",
                    evidence     = value[:4] + "***" + value[-4:],
                    location     = f"body (offset {m.start()})",
                    response_id  = "",
                    confidence   = 0.80,
                ))

        return findings
```

---

### 11. `src/ai/response_analyzer.py`

```python
class ResponseAnalyzer:
    def __init__(self, provider: str, model: str, api_key: str = None):
        self.provider = provider
        self.model    = model
        self.api_key  = api_key

    async def analyze(
        self,
        response: HTTPResponse,
        pre_extracted: list[ExtractedFinding],
        question: str | None = None
    ) -> AIAnalysisResult:
        """
        Bir HTTP response'u AI ile analiz et.
        Pre-extracted bulguları bağlam olarak ver, AI'ın bunları aşmasını iste.
        """
        prompt = self._build_prompt(response, pre_extracted, question)
        raw    = await self._call_llm(prompt)
        return self._parse(raw, response)

    def _build_prompt(
        self,
        response: HTTPResponse,
        findings: list[ExtractedFinding],
        question: str | None
    ) -> str:

        # Body'yi kısalt — token limitine dikkat
        body_preview = response.body[:3000]
        if len(response.body) > 3000:
            body_preview += f"\n... [{len(response.body)-3000} karakter kısaltıldı]"

        pre_findings_text = ""
        if findings:
            pre_findings_text = "\n## Otomatik tespit edilen bulgular\n"
            for f in findings:
                pre_findings_text += f"- [{f.severity}] {f.title}: {f.detail[:100]}\n"

        custom_q = f"\n## Özel soru\n{question}\n" if question else ""

        return f"""
Sen deneyimli bir penetrasyon test uzmanısın. Sana bir HTTP response verilecek.
Görevin bu response'u güvenlik açısından analiz edip sömürülebilecek noktaları
tespit etmek ve test önerileri sunmaktır.

## HTTP Response Bilgileri

### İstek
Method : {response.request.method if response.request else 'N/A'}
URL    : {response.request.url if response.request else 'N/A'}
Path   : {response.request.path if response.request else 'N/A'}

### Yanıt
Status : {response.status_code}
Content-Type: {response.content_type or 'bilinmiyor'}
Size   : {response.size_bytes} byte

### Önemli Headerlar
{self._format_headers(response.headers)}

### Body (ilk 3000 karakter)
{body_preview}
{pre_findings_text}
{custom_q}

## Analiz kriterleri

Şunları ara ve değerlendir:

1. **Gizli endpoint'ler**: Body içinde başka API path'leri, iç URL'ler,
   dokümante edilmemiş endpoint referansları var mı?

2. **Versiyon ve teknoloji bilgisi**: Framework, kütüphane, sunucu, veritabanı
   versiyonları tespit edildi mi? Bunlar bilinen CVE'lerle eşleşiyor mu?

3. **Hata ve debug bilgisi**: Stack trace, dosya yolları, veritabanı hataları,
   dahili IP/hostname, environment değişkenleri ifşa edilmiş mi?

4. **Gizli veri**: API key, token, parola, özel anahtar, kişisel veri (PII)
   response içinde görünür mü?

5. **Yetkilendirme zafiyeti**: Response yapısına bakarak IDOR, BOLA, aşırı
   veri ifşası (Excessive Data Exposure) ihtimali var mı?

6. **Güvenlik başlığı eksikliği**: Content-Security-Policy, HSTS,
   X-Frame-Options, X-Content-Type-Options eksik mi?

7. **İş mantığı**: Response'un yapısı ve içeriği ne tür iş mantığı
   zafiyetlerine işaret ediyor olabilir?

## Çıktı — sadece JSON döndür, başka hiçbir şey yazma:
{{
  "summary": "2-3 cümle genel değerlendirme",
  "exploitable_findings": [
    "Bulgu 1 — kısa açıklama",
    "Bulgu 2 — kısa açıklama"
  ],
  "recommended_tests": [
    "Test 1 — ne yapılmalı",
    "Test 2 — ne yapılmalı"
  ],
  "risk_level": "critical | high | medium | low | info",
  "reasoning": "Neden bu risk seviyesi (2-3 cümle)",
  "hidden_endpoints": ["/api/v2/admin", "/internal/debug"],
  "technologies_detected": ["Django 3.2", "PostgreSQL"],
  "security_headers_missing": ["CSP", "HSTS"]
}}
"""

    def _format_headers(self, headers: dict) -> str:
        interesting = [
            "server", "x-powered-by", "x-aspnet-version", "content-type",
            "set-cookie", "location", "x-frame-options", "content-security-policy",
            "strict-transport-security", "x-content-type-options",
            "access-control-allow-origin", "x-debug-token"
        ]
        lines = []
        for k in interesting:
            if k in headers:
                lines.append(f"{k}: {headers[k]}")
        return "\n".join(lines) if lines else "—"

    async def _call_llm(self, prompt: str) -> str:
        if self.provider == "ollama":
            async with aiohttp.ClientSession() as s:
                async with s.post(
                    "http://localhost:11434/api/generate",
                    json={"model": self.model, "prompt": prompt, "stream": False}
                ) as r:
                    return (await r.json())["response"]
        elif self.provider == "openai":
            import openai
            client = openai.AsyncOpenAI(api_key=self.api_key)
            resp = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2
            )
            return resp.choices[0].message.content
        raise ValueError(f"Desteklenmeyen provider: {self.provider}")

    def _parse(self, raw: str, response: HTTPResponse) -> AIAnalysisResult:
        try:
            clean = re.sub(r'```json|```', '', raw).strip()
            data  = json.loads(clean)
        except Exception:
            data = {
                "summary": raw[:300],
                "exploitable_findings": [],
                "recommended_tests": [],
                "risk_level": "info",
                "reasoning": "Parse hatası — ham çıktıya bak",
            }
        return AIAnalysisResult(
            response_id          = "",
            summary              = data.get("summary", ""),
            exploitable_findings = data.get("exploitable_findings", []),
            recommended_tests    = data.get("recommended_tests", []),
            risk_level           = Severity(data.get("risk_level", "info")),
            reasoning            = data.get("reasoning", ""),
            raw_llm_output       = raw,
        )
```

---

### 12. `src/ai/batch_processor.py`

```python
class BatchProcessor:
    def __init__(self, analyzer: ResponseAnalyzer, batch_size: int = 10):
        self.analyzer   = analyzer
        self.batch_size = batch_size

    async def process_all(
        self,
        analyzed: list[AnalyzedResponse],
        question: str | None = None
    ) -> list[AnalyzedResponse]:
        """
        Çok sayıda response'u batch'ler halinde AI ile analiz et.
        Rate limiting ve token limit aşımını engeller.
        """
        semaphore = asyncio.Semaphore(3)  # aynı anda max 3 AI çağrısı

        async def process_one(ar: AnalyzedResponse) -> AnalyzedResponse:
            async with semaphore:
                ar.ai_analysis = await self.analyzer.analyze(
                    response      = ar.response,
                    pre_extracted = ar.findings,
                    question      = question
                )
                await asyncio.sleep(0.5)  # rate limiting
                return ar

        tasks = [process_one(ar) for ar in analyzed]

        results = []
        with Progress() as progress:
            task = progress.add_task("AI analizi...", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.advance(task)

        return results
```

---

### 13. `src/correlation/attack_surface_mapper.py`

```python
class AttackSurfaceMapper:
    def build_map(
        self,
        analyzed_responses: list[AnalyzedResponse]
    ) -> AttackSurfaceMap:
        """
        Tüm response analizlerini birleştirip hedefin
        saldırı yüzeyi haritasını çıkar.
        """
        all_endpoints  = set()
        all_tech       = {}
        critical_items = []

        for ar in analyzed_responses:
            all_endpoints.update(ar.endpoints_found)
            for tech in ar.technologies:
                all_tech[tech] = tech

            for f in ar.findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    critical_items.append(f)

            if ar.ai_analysis:
                all_endpoints.update(ar.ai_analysis.raw_llm_output
                                     and []  # hidden_endpoints parse edilir
                                     or [])

        # AI ile toplu özet oluştur
        ai_summary = self._generate_summary(analyzed_responses)

        target = ""
        if analyzed_responses and analyzed_responses[0].response.request:
            from tldextract import extract as tld_extract
            t = tld_extract(analyzed_responses[0].response.request.url)
            target = t.registered_domain

        return AttackSurfaceMap(
            target          = target,
            total_responses = len(analyzed_responses),
            unique_endpoints= sorted(all_endpoints),
            technologies    = all_tech,
            critical_findings=critical_items,
            ai_summary      = ai_summary,
            generated_at    = datetime.utcnow(),
        )
```

---

### 14. `src/output/burp_annotation.py`

Burp Suite ile entegre — sonuçları Burp XML formatında annotate et:

```python
def annotate_burp_xml(
    original_xml: str,
    analysis_results: list[AnalyzedResponse],
    output_path: str
) -> None:
    """
    Orijinal Burp XML'ine AI analiz notlarını ekle.
    Burp Suite'e tekrar import edilebilir.

    Her item'a:
    - <comment>: Bulgu özeti
    - <highlight>: Severity'ye göre renk (red/orange/yellow/green)
    """
    COLORS = {
        "critical": "red",
        "high":     "orange",
        "medium":   "yellow",
        "low":      "green",
        "info":     "gray",
    }

    tree  = etree.parse(original_xml)
    items = tree.findall(".//item")

    result_map = {ar.response.request.url: ar for ar in analysis_results
                  if ar.response.request}

    for item in items:
        url = item.findtext("url") or ""
        ar  = result_map.get(url)
        if not ar:
            continue

        top_severity = "info"
        if ar.ai_analysis:
            top_severity = ar.ai_analysis.risk_level.value

        comment  = etree.SubElement(item, "comment")
        findings = [f.title for f in ar.findings[:3]]
        comment.text = f"[AI] {ar.ai_analysis.summary[:100] if ar.ai_analysis else ''} | {', '.join(findings)}"

        highlight = etree.SubElement(item, "highlight")
        highlight.text = COLORS.get(top_severity, "gray")

    tree.write(output_path, xml_declaration=True, encoding="utf-8")
```

---

### 15. `burp_extension/HttpResponseAnalyzer.py`

Burp Suite Jython eklentisi — Burp içinde doğrudan çalışır:

```python
# Burp Suite Extender → Python Environment → Jython 2.7 gerektirir
# Extensions → Add → Extension Type: Python → bu dosyayı seç

from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JButton, JTextArea, JScrollPane
import json, urllib2

class BurpExtender(IBurpExtender, IHttpListener):
    ANALYZER_URL = "http://127.0.0.1:8765/analyze"  # local API

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("AI Response Analyzer")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return  # sadece response'larla ilgileni

        resp     = messageInfo.getResponse()
        analyzed = self._helpers.analyzeResponse(resp)
        body     = resp[analyzed.getBodyOffset():].tostring()
        headers  = {str(h.split(":")[0]).lower(): str(h.split(":",1)[1]).strip()
                    for h in analyzed.getHeaders()[1:] if ":" in h}

        payload = json.dumps({
            "status_code":  analyzed.getStatusCode(),
            "headers":      headers,
            "body":         body.decode("utf-8", "ignore")[:5000],
            "url":          str(messageInfo.getUrl()),
        })

        try:
            req  = urllib2.Request(
                self.ANALYZER_URL, payload,
                {"Content-Type": "application/json"}
            )
            resp_data = json.loads(urllib2.urlopen(req, timeout=10).read())

            if resp_data.get("findings"):
                note = "[AI] " + " | ".join(
                    f["title"] for f in resp_data["findings"][:3]
                )
                self._callbacks.addToSiteMap(messageInfo)
                messageInfo.setComment(note)
                severity = resp_data.get("ai_analysis", {}).get("risk_level", "info")
                color_map = {
                    "critical": "red",   "high": "orange",
                    "medium":   "yellow","low":  "green"
                }
                messageInfo.setHighlight(color_map.get(severity, ""))
        except Exception:
            pass  # eklenti hiçbir zaman Burp'ü kilitlememeli
```

Eklentiyle birlikte çalışacak yerel API sunucusunu da implement et:

```python
# src/api_server.py — Burp eklentisinin bağlandığı yerel HTTP API
from aiohttp import web

async def analyze_endpoint(request):
    data    = await request.json()
    resp    = HTTPResponse(**data)
    result  = await engine.analyze_single(resp)
    return web.json_response(result.dict())

app = web.Application()
app.router.add_post("/analyze", analyze_endpoint)
# python -m src.api_server → port 8765
```

---

### 16. `src/core/engine.py` — Ana orkestratör

```python
class HTTPResponseAnalyzerEngine:
    def __init__(self, config: Config):
        self.config       = config
        self.burp         = BurpImporter()
        self.ep_extractor = EndpointExtractor()
        self.st_extractor = StackTraceExtractor()
        self.ver_extractor= VersionExtractor()
        self.sec_extractor= SecretExtractor()
        self.err_extractor= ErrorExtractor()
        self.fingerprinter= TechnologyFingerprinter()
        self.ai_analyzer  = ResponseAnalyzer(...) if config.ai.enabled else None
        self.batch        = BatchProcessor(self.ai_analyzer, config.ai.batch_size)
        self.correlator   = AttackSurfaceMapper()
        self.store        = SQLiteStore()

    async def analyze_single(
        self,
        response: HTTPResponse,
        question: str | None = None
    ) -> AnalyzedResponse:
        """Tek bir HTTP response'u analiz et."""

        # 1. Deterministic extractors — hepsi çalışır
        findings = []
        findings += self.ep_extractor.extract(response)      # endpoint discovery değil
        findings += self.st_extractor.extract(response)      # stack trace
        findings += self.ver_extractor.extract(response)     # versiyon
        findings += self.sec_extractor.extract(response)     # sır
        findings += self.err_extractor.extract(response)     # hata mesajları

        endpoints  = self.ep_extractor.extract_paths(response)
        technologies = self.fingerprinter.detect(response)

        # 2. AI analizi (etkinse)
        ai_result = None
        if self.ai_analyzer:
            ai_result = await self.ai_analyzer.analyze(
                response, findings, question
            )

        return AnalyzedResponse(
            response_id   = str(uuid.uuid4()),
            response      = response,
            findings      = findings,
            ai_analysis   = ai_result,
            endpoints_found = endpoints,
            technologies  = technologies,
            analyzed_at   = datetime.utcnow(),
        )

    async def analyze_burp_export(
        self,
        xml_path: str,
        question: str | None = None
    ) -> list[AnalyzedResponse]:
        """Burp XML export dosyasındaki tüm response'ları analiz et."""

        responses = self.burp.parse(xml_path)
        analyzed  = []

        with Progress() as progress:
            task = progress.add_task(
                "Deterministic analiz...", total=len(responses)
            )
            for resp in responses:
                ar = await self.analyze_single(resp)
                analyzed.append(ar)
                progress.advance(task)

        # AI batch işlemi
        if self.ai_analyzer:
            analyzed = await self.batch.process_all(analyzed, question)

        return analyzed

    async def build_attack_surface(
        self, analyzed: list[AnalyzedResponse]
    ) -> AttackSurfaceMap:
        return self.correlator.build_map(analyzed)
```

---

## TERMINAL ÇIKTISI (rich)

```
╭─ AI HTTP Response Analyzer ───────────────────────╮
│  Kaynak : burp_export.xml (143 response)          │
│  Mod    : full + AI (ollama/llama3.2)             │
╰───────────────────────────────────────────────────╯

[●] Deterministic analiz...
    ████████████████████ 143/143  [00:04]
    ✓ Stack trace    : 3 bulgu
    ✓ Versiyon ifşası: 12 bulgu
    ✓ Hata mesajı    : 8 bulgu
    ✓ Sır ifşası     : 2 bulgu
    ✓ Endpoint       : 87 benzersiz path keşfedildi

[●] AI batch analizi (143 response)...
    ████████████████████ 143/143  [02:18]

╭─ Sonuçlar ────────────────────────────────────────╮
│  🔴 Critical : 2                                 │
│    • Django debug sayfası — full stack trace      │
│    • /actuator/env — Spring env değişkenleri      │
│                                                   │
│  🟠 High     : 8                                 │
│    • MySQL hata mesajı (3 response)               │
│    • API key response body'de (2 response)        │
│                                                   │
│  🟡 Medium   : 14                                │
│  🟢 Low      : 19                                │
│                                                   │
│  Teknoloji stack  : Django 3.2, Nginx 1.24,      │
│                     PostgreSQL (versiyon bilinmiyor)│
│  Keşfedilen path  : 87                           │
│  AI önerilen test : 24 test aksiyonu             │
╰───────────────────────────────────────────────────╯
```

---

## TESTLER

**`tests/test_endpoint_extractor.py`:**
```python
def test_json_url_extracted():
    resp = make_response('{"endpoint": "/api/v2/users", "data": []}')
    found = EndpointExtractor().extract(resp)
    assert "/api/v2/users" in found

def test_html_form_action_extracted():
    resp = make_response('<form action="/admin/login" method="POST">')
    found = EndpointExtractor().extract(resp)
    assert "/admin/login" in found

def test_fetch_url_extracted():
    resp = make_response('fetch("/api/internal/config")')
    found = EndpointExtractor().extract(resp)
    assert "/api/internal/config" in found

def test_blocklist_filtered():
    resp = make_response('{"url": "/", "href": "//"}')
    found = EndpointExtractor().extract(resp)
    assert "/" not in found
    assert "//" not in found
```

**`tests/test_stack_trace_extractor.py`:**
```python
DJANGO_TRACE = """
Traceback (most recent call last):
  File "/home/app/views.py", line 42, in get
    result = User.objects.get(id=user_id)
django.core.exceptions.ObjectDoesNotExist: User matching query does not exist.
"""

def test_python_traceback_detected():
    resp     = make_response(DJANGO_TRACE)
    findings = StackTraceExtractor().extract(resp)
    assert len(findings) > 0
    assert findings[0].finding_type == FindingType.STACK_TRACE
    assert findings[0].severity == Severity.HIGH

def test_file_path_extracted():
    resp     = make_response(DJANGO_TRACE)
    findings = StackTraceExtractor().extract(resp)
    assert any("/home/app/views.py" in f.detail for f in findings)
```

**`tests/test_version_extractor.py`:**
```python
def test_server_header_version():
    resp = make_response("", headers={"server": "Apache/2.4.51 (Ubuntu)"})
    findings = VersionExtractor().extract(resp)
    assert any("2.4.51" in f.detail for f in findings)

def test_xpoweredby_version():
    resp = make_response("", headers={"x-powered-by": "PHP/8.1.0"})
    findings = VersionExtractor().extract(resp)
    assert any("8.1.0" in f.detail for f in findings)
```

---

## RUST'A GEÇİŞ YOL HARİTASI (`RUST_MIGRATION.md`)

Bu dosyayı da oluştur ve şu içeriği yaz:

```markdown
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
```

---

## README.md İÇERİĞİ

Şunları kapsayan bir README yaz:
- Kurulum adımları
- Burp Suite eklentisi kurulum rehberi (Extender → Jython kurulumu)
- Temel kullanım: dosya, Burp XML, proxy, doğrudan URL
- Tüm CLI parametreleri tablosu
- Tespit edilen bulgu tipleri açıklamaları
- Yeni pattern nasıl eklenir (YAML şablonu)
- Proxy modu ile canlı analiz nasıl yapılır
- Örnek terminal çıktısı

---

## ÖNEMLİ NOTLAR

1. Tüm ağ işlemleri `async/await` — senkron çağrı yok
2. Burp eklentisi (Jython) asla Burp'ü kilitlememelidir — tüm işlemler
   try/except ile sarılmalı ve hata sessizce loglanmalı
3. Yerel API sunucu (port 8765) sadece localhost'ta dinlemelidir
4. `max_evidence_length` ile response snippet'ları kısaltılır — log'da
   büyük response body'ler tutulmaz
5. Proxy modu filtresi: sadece JSON/HTML/XML content-type analiz edilir,
   binary dosyalar (resim, font) atlanır
6. Type hint'ler tüm fonksiyonlarda zorunlu
7. Her public fonksiyon için docstring yaz
8. `rich` ile tüm terminal çıktısı renkli ve düzenli

İmplementasyona `src/core/models.py` ve `src/core/engine.py`
dosyalarından başla; ardından sırayla `src/extractors/`,
`src/ingestion/`, `src/ai/`, `src/correlation/`, `src/output/`
modüllerine geç. Son aşamada `burp_extension/` ve `src/api_server.py`
dosyalarını implement et.
