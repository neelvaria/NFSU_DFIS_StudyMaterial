# 🔍 Automated IOC Extractor v1.0
### Digital Forensics — College Minor Project

---

## 📌 Overview

An **Automated IOC (Indicator of Compromise) Extractor** that parses
threat intelligence reports and automatically extracts, enriches, and
exports forensic artifacts used in cybersecurity investigations.

Built entirely with **Python standard library** — no external dependencies required.

---

## 🎯 What It Does

```
Input: Threat Report (TXT / HTML / JSON / LOG)
         ↓
   Extract 16 IOC Types
         ↓
   Enrich with VirusTotal API
         ↓
Output: JSON + CSV + STIX 2.1 + HTML Report
```

---

## 🧩 IOC Types Extracted

| Type              | Example                                  |
|-------------------|------------------------------------------|
| IPv4 Address      | 45.33.32.156                             |
| IPv6 Address      | 2001:db8::1                              |
| Domain Name       | malware-c2.ru                            |
| URL               | https://phishing-site.com/login          |
| MD5 Hash          | d41d8cd98f00b204e9800998ecf8427e         |
| SHA1 Hash         | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 Hash       | e3b0c44298fc1c149afbf4c8996fb924...      |
| SHA512 Hash       | cf83e1357eefb8bdf1542850d66d8007...      |
| Email Address     | attacker@protonmail.com                  |
| CVE Number        | CVE-2024-21762                           |
| Bitcoin Wallet    | 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna      |
| Windows Registry  | HKLM\SOFTWARE\Microsoft\Windows\Run\...  |
| Windows File Path | C:\Windows\Temp\malware.exe              |
| Linux File Path   | /tmp/.hidden_payload                     |
| MITRE ATT&CK      | T1566.001                                |
| ASN               | AS64496                                  |

---

## 🚀 Installation

```bash
# Clone / download project
cd ioc_extractor

# No pip install needed! Uses Python standard library only.
python3 --version   # Requires Python 3.7+
```

---

## 💻 Usage

### Basic — Extract from a file
```bash
python3 ioc_extractor.py --file report.txt
```

### With VirusTotal Enrichment
```bash
python3 ioc_extractor.py --file report.txt --vt-key YOUR_VT_API_KEY
```

### From raw text
```bash
python3 ioc_extractor.py --text "malware connects to 45.33.32.156 hash d41d8cd98f00b204e9800998ecf8427e"
```

### From stdin (pipe)
```bash
cat report.txt | python3 ioc_extractor.py --stdin
```

### Specific export format only
```bash
python3 ioc_extractor.py --file report.txt --format csv
python3 ioc_extractor.py --file report.txt --format stix
python3 ioc_extractor.py --file report.txt --format html
```

### Custom output directory
```bash
python3 ioc_extractor.py --file report.txt --output /path/to/results
```

### Extract specific IOC types only
```bash
python3 ioc_extractor.py --file report.txt --types ipv4 domain sha256
```

### Quiet mode (script-friendly, tab-separated output)
```bash
python3 ioc_extractor.py --file report.txt --quiet
```

### Interactive API key prompt
```bash
python3 ioc_extractor.py --file report.txt --prompt-key
```

---

## 📊 Output Files

| File                    | Format    | Description                          |
|-------------------------|-----------|--------------------------------------|
| ioc_report.json         | JSON      | Full structured report with metadata |
| ioc_report.csv          | CSV       | Flat table for Excel/spreadsheets    |
| ioc_report.stix.json    | STIX 2.1  | Industry-standard threat intel format|
| ioc_report.html         | HTML      | Visual dashboard (open in browser)   |

---

## 🔑 Getting a Free VirusTotal API Key

1. Go to https://www.virustotal.com
2. Create a free account
3. Go to your profile → API Key
4. Free tier: 4 requests/minute, 500/day

---

## 📁 Project Structure

```
ioc_extractor/
├── ioc_extractor.py          # Main CLI entry point
├── requirements.txt          # Dependencies (none required!)
├── README.md                 # This file
├── modules/
│   ├── extractor.py          # IOC regex + extraction engine
│   ├── parser.py             # File format parsers
│   ├── enrichment.py         # VirusTotal API integration
│   ├── exporter.py           # JSON/CSV/STIX/HTML export
│   └── display.py            # Colored terminal output
├── sample_reports/
│   └── apt_shadowNova.txt    # Sample threat report for testing
└── ioc_output/               # Generated output files
    ├── ioc_report.json
    ├── ioc_report.csv
    ├── ioc_report.stix.json
    └── ioc_report.html
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│              ioc_extractor.py (CLI)              │
│         argparse → pipeline orchestration        │
└────────────────────┬────────────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ parser.py│ │extractor │ │enrichment│
  │          │ │   .py    │ │   .py    │
  │ TXT/HTML │ │          │ │          │
  │ JSON/LOG │ │ 16 regex │ │VirusTotal│
  │ → text   │ │ patterns │ │  API v3  │
  └──────────┘ └──────────┘ └──────────┘
                     │
              ┌──────┴──────┐
              ▼             ▼
        ┌──────────┐  ┌──────────┐
        │exporter  │  │display   │
        │   .py    │  │  .py     │
        │          │  │          │
        │JSON/CSV  │  │ Colored  │
        │STIX/HTML │  │Terminal  │
        └──────────┘  └──────────┘
```

---

## 🔒 Defang Support

The tool automatically handles defanged IOCs commonly found in threat reports:

```
hxxps://evil[.]com  →  https://evil.com
1.2.3[.]4           →  1.2.3.4
user[at]domain.com  →  user@domain.com
```

---

## 📈 Enrichment Risk Levels

| Risk Level | VT Malicious Detections | Color  |
|------------|------------------------|--------|
| CRITICAL   | 10+                    | 🔴 Red |
| HIGH       | 5–9                    | 🟠 Orange |
| MEDIUM     | 1–4                    | 🟡 Yellow |
| CLEAN      | 0                      | 🟢 Green |
| UNKNOWN    | Not checked            | ⚪ Grey |

---

## 🧪 Testing

```bash
# Test with provided sample report
python3 ioc_extractor.py --file sample_reports/apt_shadowNova.txt

# Test with inline text
python3 ioc_extractor.py --text "C2 server: 45.33.32.156 hash: d41d8cd98f00b204e9800998ecf8427e CVE-2024-1234"

# Test quiet mode
python3 ioc_extractor.py --file sample_reports/apt_shadowNova.txt --quiet

# Test specific types
python3 ioc_extractor.py --file sample_reports/apt_shadowNova.txt --types ipv4 domain cve
```

---

## 🎓 Academic Information

- **Project Type:** College Minor Project
- **Domain:** Digital Forensics / Cybersecurity
- **Language:** Python 3.7+
- **Dependencies:** None (standard library only)
- **Standards:** STIX 2.1, MITRE ATT&CK, VirusTotal API v3

### Key Concepts Demonstrated
- Regex-based pattern extraction
- File format parsing
- REST API integration (VirusTotal)
- STIX 2.1 threat intelligence standard
- CLI tool design with argparse
- Modular Python architecture

---

## 🔮 Future Enhancements

- [ ] PDF and Word document parsing
- [ ] MISP platform integration
- [ ] Web scraping for blog posts
- [ ] Automatic report discovery via RSS
- [ ] ML-based context classification
- [ ] Database storage for historical tracking
- [ ] Streamlit web dashboard
- [ ] CERT-In feed integration

---

## 📄 License

MIT License — Free for academic and personal use.

---

*Built as a Digital Forensics Minor Project | 2024*