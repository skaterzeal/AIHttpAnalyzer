# httpanalyzer

**AI-augmented HTTP response triage and attack-surface mapping for penetration testers.**

`httpanalyzer` takes any pile of HTTP traffic — a Burp export, saved responses, a
live target list piped from your recon tools — and returns a **deduplicated,
CVE-correlated, AI-prioritized** view of the attack surface. It is a single
static Go binary that pipes cleanly into the rest of your workflow.

> [!NOTE]
> **Language & Migration Status:** The project has been fully migrated to Go (implemented in `cmd/httpanalyzer` and `internal/`). The legacy Python prototype files are located in the `legacy/` directory.
>
> **Configuration Note:** The Go version is configured exclusively via command-line flags and environment variables. The legacy `configs/default.yaml` file from the Python prototype is not read by the Go application.

It does not try to out-detect `nuclei` or `TruffleHog` at any single task. It
wins where no single tool helps you: **triage + trust + integration.**

```
subfinder ... | dnsx ... | dnsrecon -o jsonl | httpanalyzer analyze --stdin -o jsonl | <next tool>
```

## Why it's different

| | httpanalyzer |
|---|---|
| **CVE correlation** | Detected `Apache/2.4.49` → `CVE-2021-41773`, `CVE-2021-42013` (CVSS 9.8), offline, zero setup |
| **Trustworthy AI** | The LLM never assigns severity and never invents facts. Severity is owned by the deterministic engine + CVE data. The AI only explains, prioritizes, and suggests tests. |
| **Injection-hardened** | Response bodies (attacker-controllable) are fenced as untrusted data; prompt-injection attempts are detected and flagged. |
| **Offline-first** | Defaults to a local Ollama model — pentest data never leaves your machine. |
| **Pipeline-native** | JSONL in, JSONL out. Shares an `Asset`/`Finding` schema with the recon toolchain. |
| **Single binary** | `go install` and go — no Python, no dependency hell. |

## Install

```bash
go install github.com/skaterzeal/AIHttpAnalyzer/cmd/httpanalyzer@latest
```

Or build from source:

```bash
git clone https://github.com/skaterzeal/AIHttpAnalyzer
cd AIHttpAnalyzer
go build -o httpanalyzer ./cmd/httpanalyzer
```

## Usage

```bash
# Analyze a Burp Suite XML export
httpanalyzer analyze --burp export.xml -o jsonl

# Analyze a single saved response, with CVE correlation
httpanalyzer analyze --file response.http

# Analyze a directory of .http files into a Markdown report
httpanalyzer analyze --dir ./responses -o markdown --min-severity high

# Pipe live targets in (host or URL per line, or JSONL assets from DNSRecon)
cat hosts.txt | httpanalyzer analyze --stdin -o jsonl

# Fetch and analyze one URL (deterministic)
httpanalyzer request https://example.com/api -H "Authorization: Bearer x"

# Build a cross-asset attack surface map
httpanalyzer map --burp export.xml -o markdown

# Live MITM proxy — point your browser/Burp at it, findings stream as JSONL
httpanalyzer proxy --addr 127.0.0.1:8080

# Note: The MITM proxy generates a unique root Certificate Authority (CA) on first run.
# You must trust this cert in your browser or Burp Suite to intercept HTTPS traffic.
# The cert is saved to:
#   - Windows: %APPDATA%\httpanalyzer\ca-cert.pem
#   - Linux: ~/.config/httpanalyzer/ca-cert.pem
#   - macOS: ~/Library/Application Support/httpanalyzer/ca-cert.pem

# Full ecosystem pipe: DNS recon → live HTTP triage
dns-recon-ai scan -t example.com -o jsonl | httpanalyzer analyze --stdin -o jsonl

# Ship your own community pattern packs / CVE database (no rebuild)
httpanalyzer analyze --burp export.xml --patterns ./packs --cve-db ./cve.json

# Add advisory AI triage (local Ollama by default; severities are NOT changed).
httpanalyzer analyze --burp export.xml --ai
httpanalyzer analyze --burp export.xml --ai --llm-provider anthropic --api-key $KEY

# Note: Local AI triage (--llm-provider ollama) requires Ollama running on
# http://localhost:11434 and the default model pulled: `ollama pull llama3.2`
```

### Output formats

- **jsonl** (default) — one finding per line; pipes into the next tool. AI advice
  is emitted as separate `ai_triage` records so it never masquerades as ground truth.
- **sarif** — for CI/CD and GitHub code scanning.
- **markdown** — a human report with a severity summary and an advisory AI section.
- **html** — a self-contained, styled report (severity colors, CVEs, AI section).

## What it detects

Deterministic detectors (ground truth): stack traces, version disclosure
(→ CVE), exposed secrets (entropy-filtered, redacted), database/app error
signatures, exposed actuators / GraphQL introspection / Swagger / AWS metadata,
technology fingerprints, and discovered endpoints (filesystem-path noise filtered).

## The trust model

Severity is **always** assigned by the deterministic engine or CVE/CVSS data —
never by the LLM. The AI layer is opt-in (`--ai`) and purely advisory: it
summarizes, prioritizes the existing findings, and proposes next tests. AI-guessed
endpoints are kept explicitly `unverified` and are never merged into the verified
attack surface. If the LLM is unavailable, the deterministic report is unaffected.

## Build & release

```bash
make build      # build dist/httpanalyzer for the host
make test       # run the suite
make snapshot   # cross-platform snapshot build (needs goreleaser)
```

Tagging `vX.Y.Z` triggers the release workflow, which cross-compiles binaries for
Linux/Windows/macOS (amd64 + arm64) via GoReleaser and publishes them.

## Extending detection

Detection patterns are YAML packs embedded in the binary (`internal/extract/patterns`)
and the CVE database is `internal/cve/db.json`. Both are designed to grow —
contributions of new patterns and CVE entries are the project's roadmap.

## Status

Actively developed and tested. Implemented: ingestion (Burp/file/dir/stdin/live
request), the deterministic engine, offline CVE correlation, attack-surface
mapping, the advisory AI triage layer, a live MITM proxy, external/community
pattern packs, and an end-to-end DNSRecon → httpanalyzer JSONL pipe.

## License

MIT
