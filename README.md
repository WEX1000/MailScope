# MailScope — Python-based email analysis tool

MailScope parses `.eml` files, extracts email metadata, URLs and attachments,
detects suspicious content, and enriches findings with OSINT threat intelligence
services. Results can be saved as a structured JSON file or a full Markdown report.

---

## Features

- Parse `.eml` email files and extract headers, sender details, and message body
- Detect and normalize URLs found in the email body
- Extract attachments and compute SHA-256 hashes
- **Alert on suspicious attachment extensions** (`.exe`, `.js`, `.bat`, `.ps1`, `.vbs`, `.hta`, `.jar`, `.msi`, `.dll`, `.lnk`, and more)
- **Threat scoring (0–100)** based on all API results and heuristics, with severity levels: `CLEAN` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- OSINT enrichment via:
  - **VirusTotal** — IP, domain, and file hash reputation
  - **AbuseIPDB** — sender IP abuse confidence score
  - **Shodan** — open ports, CVEs, and tags (e.g. `malware`, `c2`, `botnet`) for the sender IP
  - **URLScan.io** — domain and URL scans
- Save results to **JSON** (`-json`) or a **Markdown report** (`-md`)

---

## Installation

```bash
git clone https://github.com/WEX1000/MailScope
cd MailScope
pip install -r requirements.txt
```

---

## Configuration

Add your API keys to `API.key`:

```
VT_API_KEY=your_virustotal_key
URLSCAN_API_KEY=your_urlscan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
```

Keys for services you don't use can be left blank — those modules are only
activated by their respective flags.

---

## Usage

```bash
python3 MailScope.py -f mail.eml [options]
```

| Flag | Description |
|------|-------------|
| `-h` | Show help |
| `-f <file>` | Path to `.eml` file *(required)* |
| `-vt` | Enable VirusTotal (IP, domain, file hashes) |
| `-abuse` | Enable AbuseIPDB (sender IP) |
| `-shodan` | Enable Shodan (sender IP) |
| `-url` | Enable URLScan.io (domain + URLs) |
| `-json` | Save full results to a JSON file |
| `-md` | Save full results to a Markdown report |

### Examples

Basic analysis:
```bash
python3 MailScope.py -f suspicious.eml
```

Full OSINT enrichment with Markdown report:
```bash
python3 MailScope.py -f suspicious.eml -vt -abuse -shodan -url -md
```

All features, save both output formats:
```bash
python3 MailScope.py -f suspicious.eml -vt -abuse -shodan -url -json -md
```

---

## Threat Scoring

MailScope calculates a threat score (0–100) from six independent components:

| Component | Max points |
|-----------|-----------|
| VirusTotal — sender IP | 20 |
| VirusTotal — sender domain | 20 |
| VirusTotal — attachment hash | 20 |
| AbuseIPDB — sender IP | 20 |
| Suspicious attachment extensions | 15 |
| Shodan — tags / CVEs / open ports | 5 |

**Severity levels:**

| Score | Level |
|-------|-------|
| 0 | CLEAN |
| 1–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

---

## Output

### Terminal

Color-coded output with sections for email metadata, URLs, attachments
(with inline suspicious-extension alerts), OSINT results, and the threat score banner.

### JSON (`-json`)

Saved as `<filename>.eml_Analysis.json`:

```json
{
  "analysis_data": { ... },
  "osint_data":    { ... },
  "threat_score":  { "score": 75, "level": "CRITICAL", "reasons": [ ... ] }
}
```

### Markdown (`-md`)

Saved as `<filename>.eml_MailScope_Report.md` — a full human-readable report
with tables for metadata, attachments, threat score breakdown, and all OSINT sections.

---

## Project structure

```
MailScope/
├── MailScope.py        # Entry point, CLI, display logic
├── API.key             # API keys (not committed)
├── requirements.txt
└── app/
    ├── analyzer.py     # Email parsing, attachment hashing, extension detection
    ├── scoring.py      # Threat score engine (0-100)
    ├── report.py       # Markdown report generator
    ├── osintdata.py    # OSINT orchestration
    ├── vt.py           # VirusTotal API
    ├── abuseipdb.py    # AbuseIPDB API
    ├── shodan.py       # Shodan API
    ├── urlscan.py      # URLScan.io API
    ├── config.py       # API key loader
    └── utils.py        # URL regex and deduplication
```
