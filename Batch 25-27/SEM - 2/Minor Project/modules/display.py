"""
CLI Display Module
Renders colored terminal output without any external libraries
Uses raw ANSI escape codes
"""

import os
import sys

# ─────────────────────────────────────────────
#  ANSI Colors
# ─────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

BLACK   = "\033[30m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"

BG_BLACK = "\033[40m"
BG_RED   = "\033[41m"
BG_BLUE  = "\033[44m"

BRIGHT_RED     = "\033[91m"
BRIGHT_GREEN   = "\033[92m"
BRIGHT_YELLOW  = "\033[93m"
BRIGHT_BLUE    = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN    = "\033[96m"
BRIGHT_WHITE   = "\033[97m"

# Check if terminal supports color
def supports_color():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def c(text, *codes):
    if not supports_color():
        return str(text)
    return "".join(codes) + str(text) + RESET


# ─────────────────────────────────────────────
#  IOC Type Colors & Icons
# ─────────────────────────────────────────────

IOC_STYLE = {
    "ipv4":              (BRIGHT_CYAN,    "IP v4      "),
    "ipv6":              (BRIGHT_CYAN,    "IP v6      "),
    "domain":            (BRIGHT_BLUE,    "Domain     "),
    "url":               (BRIGHT_MAGENTA, "URL        "),
    "md5":               (BRIGHT_YELLOW,  "MD5 Hash   "),
    "sha1":              (BRIGHT_YELLOW,  "SHA1 Hash  "),
    "sha256":            (BRIGHT_YELLOW,  "SHA256 Hash"),
    "sha512":            (BRIGHT_YELLOW,  "SHA512 Hash"),
    "email":             (GREEN,          "Email      "),
    "cve":               (BRIGHT_RED,     "CVE        "),
    "bitcoin_wallet":    (YELLOW,         "BTC Wallet "),
    "registry_key":      (WHITE,          "Registry   "),
    "file_path_windows": (WHITE,          "Win Path   "),
    "file_path_linux":   (WHITE,          "Linux Path "),
    "mitre_attack":      (BRIGHT_RED,     "MITRE ATT&CK"),
    "asn":               (CYAN,           "ASN        "),
}

RISK_STYLE = {
    "critical": (BRIGHT_RED,    "● CRITICAL"),
    "high":     (BRIGHT_YELLOW, "● HIGH    "),
    "medium":   (YELLOW,        "● MEDIUM  "),
    "clean":    (BRIGHT_GREEN,  "● CLEAN   "),
    "unknown":  (DIM + WHITE,   "● UNKNOWN "),
}


def print_banner():
    banner = f"""
{c('╔══════════════════════════════════════════════════════════════╗', BRIGHT_BLUE, BOLD)}
{c('║', BRIGHT_BLUE)}  {c('AUTOMATED IOC EXTRACTOR', BRIGHT_CYAN, BOLD)}  {c('v1.0', DIM)}  {c('|', DIM)}  {c('Digital Forensics Tool', DIM)}  {c('║', BRIGHT_BLUE)}
{c('║', BRIGHT_BLUE)}  {c('Extract · Enrich · Analyze · Export', DIM)}                       {c('║', BRIGHT_BLUE)}
{c('╚══════════════════════════════════════════════════════════════╝', BRIGHT_BLUE, BOLD)}
"""
    print(banner)


def print_section(title: str):
    width = 64
    print(f"\n{c('─' * width, DIM)}")
    print(f"  {c(title, BRIGHT_CYAN, BOLD)}")
    print(f"{c('─' * width, DIM)}")


def print_ioc_table(iocs: dict):
    if not iocs:
        print(f"  {c('No IOCs found.', DIM)}")
        return

    for ioc_type, values in sorted(iocs.items()):
        color, label = IOC_STYLE.get(ioc_type, (WHITE, ioc_type.ljust(11)))
        count_str = c(f"[{len(values)}]", BRIGHT_WHITE, BOLD)
        print(f"\n  {c(label, color, BOLD)} {count_str}")
        for val in values[:20]:  # Show max 20 per type
            print(f"    {c('›', DIM)} {val}")
        if len(values) > 20:
            print(f"    {c(f'... and {len(values)-20} more', DIM)}")


def print_summary(iocs: dict):
    total = sum(len(v) for v in iocs.values())
    print_section("EXTRACTION SUMMARY")

    print(f"\n  {c('Total IOCs Found:', BOLD)} {c(str(total), BRIGHT_GREEN, BOLD)}\n")

    for ioc_type, values in sorted(iocs.items()):
        color, label = IOC_STYLE.get(ioc_type, (WHITE, ioc_type.ljust(11)))
        bar_len = min(len(values), 30)
        bar = "█" * bar_len
        print(f"  {c(label, color)}  {c(bar, color)}{c(f'  {len(values)}', BOLD)}")


def print_enrichment(enriched: dict):
    if not enriched:
        print(f"  {c('No enrichment data (VT API key not provided)', DIM)}")
        return

    print_section("VIRUSTOTAL ENRICHMENT")

    for ioc_type, items in enriched.items():
        color, label = IOC_STYLE.get(ioc_type, (WHITE, ioc_type))
        print(f"\n  {c(label, color, BOLD)}")

        for item in items:
            val     = item.get("value", "")
            risk    = item.get("risk_level", "unknown")
            status  = item.get("vt_status", "")
            mal     = item.get("malicious", 0)
            tot     = item.get("total_engines", 0)
            family  = item.get("malware_family", "")
            country = item.get("country", "")

            risk_color, risk_label = RISK_STYLE.get(risk, (WHITE, risk))

            if status == "not_checked":
                print(f"    {c('›', DIM)} {val[:60]:<60}  {c('not checked', DIM)}")
            elif status in ("not_found", "rate_limited"):
                print(f"    {c('›', DIM)} {val[:60]:<60}  {c(status, DIM)}")
            else:
                det_str = f"{mal}/{tot}" if tot else "—"
                fam_str = f"  {c(family, BRIGHT_RED)}" if family else ""
                cty_str = f"  {c(country, DIM)}" if country else ""
                print(f"    {c('›', DIM)} {val[:55]:<55}  "
                      f"{c(risk_label, risk_color)}  {det_str}{fam_str}{cty_str}")


def print_export_paths(paths: dict):
    print_section("EXPORTED FILES")
    icons = {"json": "📄", "csv": "📊", "stix": "🔰", "html": "🌐"}
    for fmt, path in paths.items():
        icon = icons.get(fmt, "📁")
        print(f"  {icon}  {c(fmt.upper(), BOLD)}  →  {c(path, BRIGHT_CYAN)}")


def print_progress(current: int, total: int, label: str = ""):
    pct = int((current / total) * 30) if total else 0
    bar = "█" * pct + "░" * (30 - pct)
    sys.stdout.write(f"\r  {c(bar, BRIGHT_BLUE)} {current}/{total}  {label}    ")
    sys.stdout.flush()
    if current == total:
        print()


def print_error(msg: str):
    print(f"\n  {c('✖ ERROR:', BRIGHT_RED, BOLD)} {msg}")


def print_success(msg: str):
    print(f"\n  {c('✔', BRIGHT_GREEN, BOLD)} {msg}")


def print_info(msg: str):
    print(f"  {c('ℹ', BRIGHT_CYAN)} {msg}")


def prompt_api_key() -> str:
    """Prompt user for VirusTotal API key securely."""
    import getpass
    print(f"\n  {c('VirusTotal API Key', BRIGHT_YELLOW)} "
          f"{c('(press Enter to skip enrichment):', DIM)}")
    try:
        return getpass.getpass("  > ").strip()
    except Exception:
        return input("  > ").strip()