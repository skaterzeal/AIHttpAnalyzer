# Burp Suite Extender → Python Environment → Jython 2.7 gerektirir
# Extensions → Add → Extension Type: Python → bu dosyayı seç

from burp import IBurpExtender, IHttpListener
from java.lang import Thread, Runnable
import json
import urllib2


class BurpExtender(IBurpExtender, IHttpListener):
    ANALYZER_URL = "http://127.0.0.1:8765/analyze"  # local API

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AI Response Analyzer")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return  # sadece response'larla ilgilen

        try:
            resp = messageInfo.getResponse()
            if resp is None:
                return

            # Response parse et
            analyzed = self._helpers.analyzeResponse(resp)
            body = resp[analyzed.getBodyOffset():].tostring()
            headers = {
                str(h.split(":")[0]).lower(): str(h.split(":", 1)[1]).strip()
                for h in analyzed.getHeaders()[1:]
                if ":" in h
            }

            # Request parse et (İstek Bağlamı)
            req_bytes = messageInfo.getRequest()
            req_headers = {}
            req_body = ""
            method = "GET"
            path = "/"
            url = str(messageInfo.getUrl())

            if req_bytes is not None:
                request_info = self._helpers.analyzeRequest(messageInfo)
                method = request_info.getMethod()
                path = request_info.getUrl().getPath()
                req_body_offset = request_info.getBodyOffset()
                req_body = req_bytes[req_body_offset:].tostring()
                req_headers = {
                    str(h.split(":")[0]).lower(): str(h.split(":", 1)[1]).strip()
                    for h in request_info.getHeaders()[1:]
                    if ":" in h
                }

            payload = json.dumps({
                "status_code": analyzed.getStatusCode(),
                "headers": headers,
                "body": body.decode("utf-8", "ignore")[:1048576],  # limit 1MB
                "content_type": headers.get("content-type"),
                "size_bytes": len(body),
                "response_time_ms": None,
                "source": "burp",
                "request": {
                    "method": method,
                    "url": url,
                    "path": path,
                    "headers": req_headers,
                    "body": req_body.decode("utf-8", "ignore")[:262144] if req_body else None,  # limit 256KB for request body
                    "timestamp": None
                }
            })

            # Asenkron analiz görevi başlat
            task = AnalysisTask(self._callbacks, self._helpers, messageInfo, self.ANALYZER_URL, payload)
            Thread(task).start()

        except Exception:
            pass  # eklenti hiçbir zaman Burp'ü kilitlememeli


class AnalysisTask(Runnable):
    def __init__(self, callbacks, helpers, message_info, url, payload):
        self._callbacks = callbacks
        self._helpers = helpers
        self._message_info = message_info
        self._url = url
        self._payload = payload

    def run(self):
        try:
            req = urllib2.Request(
                self._url, self._payload,
                {"Content-Type": "application/json"}
            )
            resp_data = json.loads(urllib2.urlopen(req, timeout=15).read())

            if resp_data.get("findings"):
                note = "[AI] " + " | ".join(
                    f["title"] for f in resp_data["findings"][:3]
                )
                self._callbacks.addToSiteMap(self._message_info)
                self._message_info.setComment(note)
                
                severity = "info"
                ai = resp_data.get("ai_analysis")
                if ai and ai.get("risk_level"):
                    severity = ai["risk_level"]
                
                color_map = {
                    "critical": "red",
                    "high": "orange",
                    "medium": "yellow",
                    "low": "green"
                }
                self._message_info.setHighlight(color_map.get(severity, ""))
        except Exception:
            pass

