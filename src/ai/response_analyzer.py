from __future__ import annotations

import json
import re

import aiohttp

from src.core.models import (
    HTTPResponse,
    ExtractedFinding,
    AIAnalysisResult,
    Severity,
)
from src.ai.context_builder import ContextBuilder
from src.ai.exploit_suggester import ExploitSuggester
from src.ai.smart_truncator import SmartTruncator


class ResponseAnalyzer:
    """Analyze HTTP responses using an LLM."""

    def __init__(self, provider: str, model: str, api_key: str | None = None):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.context_builder = ContextBuilder()
        self.exploit_suggester = ExploitSuggester()
        self.smart_truncator = SmartTruncator()

    async def analyze(
        self,
        response: HTTPResponse,
        pre_extracted: list[ExtractedFinding],
        question: str | None = None,
    ) -> AIAnalysisResult:
        """
        Bir HTTP response'u AI ile analiz et.
        Pre-extracted bulguları bağlam olarak ver, AI'ın bunları aşmasını iste.
        """
        prompt = self._build_prompt(response, pre_extracted, question)
        raw = await self._call_llm(prompt)
        return self._parse(raw, response)

    def _build_prompt(
        self,
        response: HTTPResponse,
        findings: list[ExtractedFinding],
        question: str | None,
    ) -> str:
        # Smart Truncation
        body_preview = self.smart_truncator.truncate(response.body, findings, max_length=4000)

        # HTTP Request Context formatting
        request_text = "N/A"
        if response.request:
            req = response.request
            req_headers_lines = []
            for k, v in req.headers.items():
                if k.lower() in ["authorization", "cookie", "xsrf-token", "csrf-token"]:
                    req_headers_lines.append(f"{k}: [REDACTED]")
                else:
                    req_headers_lines.append(f"{k}: {v}")
            req_headers_str = "\n".join(req_headers_lines) if req_headers_lines else "—"
            
            req_body_preview = req.body or "—"
            if req.body and len(req.body) > 1000:
                req_body_preview = req.body[:1000] + f"\n... [{len(req.body)-1000} karakter kısaltıldı]"
                
            request_text = f"""HTTP Metodu: {req.method}
İstek URL'i: {req.url}
İstek Path'i: {req.path}
İstek Header'ları:
{req_headers_str}

İstek Body'si:
{req_body_preview}"""

        # Use ContextBuilder
        context_text = self.context_builder.build(response, findings)

        # Use ExploitSuggester
        suggestions = self.exploit_suggester.suggest(findings)
        suggestions_text = ""
        if suggestions:
            suggestions_text = "\n## Önerilen Ön Testler (Exploit Suggestions):\n" + "\n".join(f"- {s}" for s in suggestions) + "\n"

        custom_q = f"\n## Özel soru\n{question}\n" if question else ""

        return f"""\
Sen deneyimli bir penetrasyon test uzmanısın. Sana bir HTTP isteği (Request) ve buna dönen HTTP yanıtı (Response) verilecek.
Görevin bu istek ve yanıt çiftini güvenlik açısından analiz edip sömürülebilecek noktaları
tespit etmek ve test önerileri sunmaktır.

## HTTP Request Bilgileri ve Bağlam
{request_text}

## HTTP Response Bilgileri ve Bağlam
{context_text}

### Body (Smart Preview)
{body_preview}

{suggestions_text}
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

5. **Yetkilendirme zafiyeti**: İstekteki parametreler ile yanıttaki veriye bakarak IDOR, BOLA, aşırı
   veri ifşası (Excessive Data Exposure) ihtimali var mı?

6. **Güvenlik başlığı eksikliği**: Content-Security-Policy, HSTS,
   X-Frame-Options, X-Content-Type-Options eksik mi?

7. **İş mantığı**: Request ve Response'un yapısı ve içeriği ne tür iş mantığı
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
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "content-type",
            "set-cookie",
            "location",
            "x-frame-options",
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "access-control-allow-origin",
            "x-debug-token",
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
                    json={"model": self.model, "prompt": prompt, "stream": False},
                ) as r:
                    return (await r.json())["response"]
        elif self.provider == "openai":
            import openai

            client = openai.AsyncOpenAI(api_key=self.api_key)
            resp = await client.chat.completions.create(
                model=self.model or "gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )
            return resp.choices[0].message.content
        elif self.provider == "anthropic":
            async with aiohttp.ClientSession() as s:
                headers = {
                    "x-api-key": self.api_key or "",
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                }
                payload = {
                    "model": self.model or "claude-3-5-sonnet-20240620",
                    "max_tokens": 2000,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ]
                }
                async with s.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=headers,
                    json=payload,
                ) as r:
                    if r.status != 200:
                        err_text = await r.text()
                        raise RuntimeError(f"Anthropic API Hatası (Status {r.status}): {err_text}")
                    resp_json = await r.json()
                    return resp_json["content"][0]["text"]
        raise ValueError(f"Desteklenmeyen provider: {self.provider}")

    def _parse(self, raw: str, response: HTTPResponse) -> AIAnalysisResult:
        try:
            clean = re.sub(r"```json|```", "", raw).strip()
            data = json.loads(clean)
        except Exception:
            try:
                start_idx = raw.find("{")
                end_idx = raw.rfind("}")
                if start_idx != -1 and end_idx != -1:
                    json_str = raw[start_idx : end_idx + 1]
                    data = json.loads(json_str)
                else:
                    raise ValueError("JSON block not found")
            except Exception:
                data = {
                    "summary": raw[:300],
                    "exploitable_findings": [],
                    "recommended_tests": [],
                    "risk_level": "info",
                    "reasoning": "Parse hatası — ham çıktıya bak",
                    "hidden_endpoints": [],
                    "technologies_detected": [],
                    "security_headers_missing": [],
                }
        return AIAnalysisResult(
            response_id="",
            summary=data.get("summary", ""),
            exploitable_findings=data.get("exploitable_findings", []),
            recommended_tests=data.get("recommended_tests", []),
            risk_level=Severity(data.get("risk_level", "info")),
            reasoning=data.get("reasoning", ""),
            raw_llm_output=raw,
            hidden_endpoints=data.get("hidden_endpoints", []),
            technologies_detected=data.get("technologies_detected", []),
            security_headers_missing=data.get("security_headers_missing", []),
        )
