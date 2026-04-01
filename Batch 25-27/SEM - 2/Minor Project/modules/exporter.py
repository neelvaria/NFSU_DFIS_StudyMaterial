"""
Export Module
Exports extracted IOCs to CSV, JSON, and STIX 2.1 formats
Uses only Python standard library
"""

import csv
import json
import os
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _report_id() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────
#  JSON Export
# ─────────────────────────────────────────────

def export_json(iocs: dict, enriched: dict, output_path: str, source: str = "") -> str:
    """Export IOCs and enrichment data as JSON."""
    report = {
        "report_metadata": {
            "generated_at": _timestamp(),
            "source": source,
            "report_id": _report_id(),
            "tool": "Automated IOC Extractor v1.0",
            "total_iocs": sum(len(v) for v in iocs.values()),
        },
        "ioc_summary": {k: len(v) for k, v in iocs.items()},
        "iocs": iocs,
        "enrichment": enriched,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return output_path


# ─────────────────────────────────────────────
#  CSV Export
# ─────────────────────────────────────────────

def export_csv(iocs: dict, enriched: dict, output_path: str) -> str:
    """Export IOCs as flat CSV with enrichment columns."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Build enrichment lookup
    enrich_lookup: Dict[str, dict] = {}
    for ioc_type, items in enriched.items():
        for item in items:
            enrich_lookup[item.get("value", "")] = item

    fieldnames = [
        "ioc_type", "value",
        "vt_malicious", "vt_suspicious", "vt_total_engines",
        "risk_level", "malware_family", "country", "tags"
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for ioc_type, values in iocs.items():
            for val in values:
                enrich = enrich_lookup.get(val, {})
                writer.writerow({
                    "ioc_type":          ioc_type,
                    "value":             val,
                    "vt_malicious":      enrich.get("malicious", ""),
                    "vt_suspicious":     enrich.get("suspicious", ""),
                    "vt_total_engines":  enrich.get("total_engines", ""),
                    "risk_level":        enrich.get("risk_level", ""),
                    "malware_family":    enrich.get("malware_family", ""),
                    "country":           enrich.get("country", ""),
                    "tags":              "|".join(enrich.get("tags", [])),
                })

    return output_path


# ─────────────────────────────────────────────
#  STIX 2.1 Export (manual, no external lib)
# ─────────────────────────────────────────────

STIX_TYPE_MAP = {
    "ipv4":   ("ipv4-addr",    "value"),
    "ipv6":   ("ipv6-addr",    "value"),
    "domain": ("domain-name",  "value"),
    "url":    ("url",          "value"),
    "md5":    ("file",         "hashes.MD5"),
    "sha1":   ("file",         "hashes.SHA-1"),
    "sha256": ("file",         "hashes.SHA-256"),
    "email":  ("email-addr",   "value"),
}


def _make_stix_id(stix_type: str) -> str:
    return f"{stix_type}--{str(uuid.uuid4())}"


def _make_indicator(ioc_type: str, value: str, risk_level: str = "") -> dict:
    """Create a STIX 2.1 Indicator object."""
    ts = _timestamp()

    # Build pattern
    if ioc_type == "ipv4":
        pattern = f"[ipv4-addr:value = '{value}']"
    elif ioc_type == "ipv6":
        pattern = f"[ipv6-addr:value = '{value}']"
    elif ioc_type == "domain":
        pattern = f"[domain-name:value = '{value}']"
    elif ioc_type == "url":
        pattern = f"[url:value = '{value}']"
    elif ioc_type == "md5":
        pattern = f"[file:hashes.MD5 = '{value}']"
    elif ioc_type == "sha1":
        pattern = f"[file:hashes.'SHA-1' = '{value}']"
    elif ioc_type == "sha256":
        pattern = f"[file:hashes.'SHA-256' = '{value}']"
    elif ioc_type == "email":
        pattern = f"[email-addr:value = '{value}']"
    elif ioc_type == "cve":
        pattern = f"[vulnerability:name = '{value}']"
    else:
        pattern = f"[artifact:payload_bin = '{value}']"

    labels = ["malicious-activity"]
    if risk_level in ("critical", "high"):
        labels.append("anomalous-activity")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _make_stix_id("indicator"),
        "created": ts,
        "modified": ts,
        "name": f"{ioc_type.upper()}: {value}",
        "description": f"IOC extracted by Automated IOC Extractor. Risk: {risk_level or 'unknown'}",
        "indicator_types": labels,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "confidence": _risk_to_confidence(risk_level),
    }


def _risk_to_confidence(risk: str) -> int:
    return {"critical": 95, "high": 80, "medium": 55, "clean": 10}.get(risk, 50)


def export_stix(iocs: dict, enriched: dict, output_path: str, source: str = "") -> str:
    """Export IOCs as STIX 2.1 Bundle JSON."""
    ts = _timestamp()
    bundle_id = _make_stix_id("bundle")

    # Build enrichment lookup
    enrich_lookup: Dict[str, dict] = {}
    for ioc_type, items in enriched.items():
        for item in items:
            enrich_lookup[item.get("value", "")] = item

    objects = []

    # Identity object (our tool)
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _make_stix_id("identity"),
        "created": ts,
        "modified": ts,
        "name": "Automated IOC Extractor",
        "identity_class": "tool",
        "description": f"Source report: {source}",
    }
    objects.append(identity)

    # Indicator objects
    supported = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve"}
    for ioc_type, values in iocs.items():
        if ioc_type not in supported:
            continue
        for val in values:
            enrich = enrich_lookup.get(val, {})
            risk = enrich.get("risk_level", "")
            indicator = _make_indicator(ioc_type, val, risk)
            objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    return output_path


# ─────────────────────────────────────────────
#  HTML Report Export
# ─────────────────────────────────────────────

RISK_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "clean":    "#44bb44",
    "unknown":  "#888888",
}

IOC_ICONS = {
    "ipv4":              "🌐",
    "ipv6":              "🌐",
    "domain":            "🔗",
    "url":               "🔗",
    "md5":               "🔒",
    "sha1":              "🔒",
    "sha256":            "🔒",
    "sha512":            "🔒",
    "email":             "📧",
    "cve":               "⚠️",
    "bitcoin_wallet":    "₿",
    "registry_key":      "🗝️",
    "file_path_windows": "📁",
    "file_path_linux":   "📁",
    "mitre_attack":      "🎯",
    "asn":               "📡",
}


def export_html(iocs: dict, enriched: dict, output_path: str, source: str = "") -> str:
    """Export a self-contained HTML report."""
    ts = _timestamp()
    total = sum(len(v) for v in iocs.values())

    enrich_lookup: Dict[str, dict] = {}
    for ioc_type, items in enriched.items():
        for item in items:
            enrich_lookup[item.get("value", "")] = item

    # Count risk levels
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "clean": 0, "unknown": 0}
    for items in enriched.values():
        for item in items:
            r = item.get("risk_level", "unknown")
            risk_counts[r] = risk_counts.get(r, 0) + 1

    rows = []
    for ioc_type, values in sorted(iocs.items()):
        for val in values:
            enrich = enrich_lookup.get(val, {})
            icon = IOC_ICONS.get(ioc_type, "•")

            if not enrich:
                # IOC was not sent to VirusTotal
                rows.append(f"""
        <tr data-type="{ioc_type}">
          <td>{icon} {ioc_type}</td>
          <td class="mono">{val}</td>
          <td><span class="badge" style="background:#444;color:#aaa">NOT CHECKED</span></td>
          <td style="color:#666">—</td>
          <td style="color:#666">—</td>
        </tr>""")
            else:
                risk      = enrich.get("risk_level", "unknown")
                color     = RISK_COLORS.get(risk, "#888888")
                mal       = enrich.get("malicious", 0)
                tot       = enrich.get("total_engines", 0)
                fam       = enrich.get("malware_family", "") or "None detected"
                vt_status = enrich.get("vt_status", "")

                if vt_status in ("not_found", "rate_limited", "unknown", "not_checked"):
                    det_str = "—"
                    fam_str = "—"
                    risk    = "unknown"
                    color   = "#888888"
                else:
                    det_str = f"{mal} / {tot}"
                    fam_str = fam

                rows.append(f"""
        <tr data-type="{ioc_type}">
          <td>{icon} {ioc_type}</td>
          <td class="mono">{val}</td>
          <td><span class="badge" style="background:{color}">{risk.upper()}</span></td>
          <td>{det_str}</td>
          <td>{fam_str}</td>
        </tr>""")

    summary_cards = ""
    for ioc_type, values in sorted(iocs.items()):
        icon = IOC_ICONS.get(ioc_type, "•")
        summary_cards += f"""
      <div class="card" data-type="{ioc_type}" onclick="filterByType('{ioc_type}')" title="Click to filter {ioc_type}">
        <div class="card-icon">{icon}</div>
        <div class="card-count">{len(values)}</div>
        <div class="card-label">{ioc_type.upper()}</div>
      </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IOC Extraction Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }}

  /* ── Header ── */
  .header {{ background: linear-gradient(135deg, #1f2937, #111827);
             border-bottom: 2px solid #30363d; padding: 24px 32px; }}
  .header h1 {{ font-size: 24px; color: #58a6ff; }}
  .header p  {{ color: #8b949e; margin-top: 4px; font-size: 13px; }}

  /* ── Main ── */
  .main {{ padding: 24px 32px; }}

  /* ── Cards ── */
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }}
  .card {{
    background: #161b22; border: 2px solid #30363d; border-radius: 10px;
    padding: 14px 18px; text-align: center; min-width: 110px;
    cursor: pointer; transition: all 0.2s ease; user-select: none;
  }}
  .card:hover {{
    border-color: #58a6ff; background: #1f2937;
    transform: translateY(-2px); box-shadow: 0 4px 12px rgba(88,166,255,0.2);
  }}
  .card.active {{
    border-color: #58a6ff; background: #1c2d40;
    box-shadow: 0 0 0 3px rgba(88,166,255,0.3);
  }}
  .card.dimmed {{ opacity: 0.35; }}
  .card-icon  {{ font-size: 22px; }}
  .card-count {{ font-size: 28px; font-weight: bold; color: #58a6ff; }}
  .card-label {{ font-size: 10px; color: #8b949e; margin-top: 4px; letter-spacing: 0.5px; }}

  /* ── Filter Bar ── */
  .filter-bar {{
    display: flex; align-items: center; gap: 12px;
    margin-bottom: 16px; flex-wrap: wrap;
  }}
  .filter-label {{
    font-size: 13px; color: #8b949e; font-weight: 600;
  }}
  .filter-active {{
    background: #1c2d40; border: 1px solid #58a6ff;
    color: #58a6ff; padding: 6px 14px; border-radius: 20px;
    font-size: 13px; font-weight: 600; display: none;
  }}
  .show-all-btn {{
    background: #21262d; border: 1px solid #30363d;
    color: #c9d1d9; padding: 7px 16px; border-radius: 20px;
    font-size: 13px; cursor: pointer; transition: all 0.2s;
    font-weight: 600;
  }}
  .show-all-btn:hover {{ background: #30363d; border-color: #58a6ff; color: #58a6ff; }}
  .show-all-btn.active {{ background: #1c2d40; border-color: #58a6ff; color: #58a6ff; }}

  /* ── Result count ── */
  .result-count {{
    font-size: 12px; color: #8b949e; margin-left: auto;
  }}
  .result-count span {{ color: #58a6ff; font-weight: bold; }}

  /* ── Risk Bar ── */
  .risk-bar {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }}
  .risk-pill {{
    padding: 6px 14px; border-radius: 20px; font-size: 13px;
    font-weight: 600; cursor: pointer; transition: all 0.2s; opacity: 0.9;
  }}
  .risk-pill:hover {{ opacity: 1; transform: scale(1.05); }}

  /* ── Search ── */
  .search-wrap {{ margin-bottom: 16px; }}
  .search-input {{
    width: 100%; padding: 10px 16px; border-radius: 8px;
    background: #161b22; border: 1px solid #30363d;
    color: #c9d1d9; font-size: 13px; outline: none;
    transition: border-color 0.2s;
  }}
  .search-input:focus {{ border-color: #58a6ff; }}
  .search-input::placeholder {{ color: #484f58; }}

  /* ── Table ── */
  .table-wrap {{
    background: #161b22; border: 1px solid #30363d;
    border-radius: 10px; overflow: hidden;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: #1f2937; color: #8b949e; padding: 11px 14px;
    text-align: left; font-size: 11px; text-transform: uppercase;
    letter-spacing: 0.8px; position: sticky; top: 0; z-index: 1;
  }}
  td {{ padding: 10px 14px; border-top: 1px solid #21262d; font-size: 13px; }}
  tr:hover td {{ background: #1f2937; }}
  tr.hidden {{ display: none; }}
  .mono {{
    font-family: 'Courier New', monospace; font-size: 11px;
    word-break: break-all; color: #79c0ff;
  }}
  .badge {{
    padding: 3px 10px; border-radius: 12px; font-size: 11px;
    font-weight: bold; color: #000; white-space: nowrap;
  }}

  /* ── No results ── */
  .no-results {{
    text-align: center; padding: 40px; color: #484f58;
    font-size: 14px; display: none;
  }}

  /* ── Copy button ── */
  .copy-btn {{
    background: none; border: 1px solid #30363d; color: #8b949e;
    padding: 2px 8px; border-radius: 4px; font-size: 10px;
    cursor: pointer; margin-left: 6px; transition: all 0.15s;
    vertical-align: middle;
  }}
  .copy-btn:hover {{ border-color: #58a6ff; color: #58a6ff; }}

  /* ── Footer ── */
  .footer {{ text-align: center; padding: 20px; color: #8b949e; font-size: 12px; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 Automated IOC Extractor — Threat Report</h1>
  <p>
    Source: <strong>{source or 'Direct Input'}</strong>
    &nbsp;|&nbsp; Generated: {ts}
    &nbsp;|&nbsp; Total IOCs: <strong>{sum(len(v) for v in iocs.values())}</strong>
  </p>
</div>

<div class="main">

  <!-- IOC Type Cards -->
  <div class="cards" id="cards">
    {summary_cards}
  </div>

  <!-- Filter bar -->
  <div class="filter-bar">
    <span class="filter-label">🔽 Filter:</span>
    <button class="show-all-btn active" id="showAllBtn" onclick="showAll()">
      🗂 Show All IOCs
    </button>
    <span class="filter-active" id="filterActive"></span>
    <span class="result-count" id="resultCount">
      Showing <span id="visibleCount">{sum(len(v) for v in iocs.values())}</span>
      of {sum(len(v) for v in iocs.values())} IOCs
    </span>
  </div>

  <!-- Search -->
  <div class="search-wrap">
    <input class="search-input" id="searchInput" type="text"
           placeholder="🔎  Search IOCs by value, type, risk, or malware family..."
           oninput="applyFilters()" />
  </div>

  <!-- Risk Pills -->
  <div class="risk-bar">
    <span class="risk-pill" style="background:#ff4444;color:#000"
          onclick="filterByRisk('critical')">
      🔴 Critical: {risk_counts['critical']}
    </span>
    <span class="risk-pill" style="background:#ff8800;color:#000"
          onclick="filterByRisk('high')">
      🟠 High: {risk_counts['high']}
    </span>
    <span class="risk-pill" style="background:#ffcc00;color:#000"
          onclick="filterByRisk('medium')">
      🟡 Medium: {risk_counts['medium']}
    </span>
    <span class="risk-pill" style="background:#44bb44;color:#000"
          onclick="filterByRisk('clean')">
      🟢 Clean: {risk_counts['clean']}
    </span>
    <span class="risk-pill" style="background:#888;color:#fff"
          onclick="filterByRisk('unknown')">
      ⚪ Unknown: {risk_counts['unknown']}
    </span>
    <span class="risk-pill" style="background:#444;color:#aaa"
          onclick="filterByRisk('not checked')">
      ⬜ Not Checked
    </span>
  </div>

  <!-- IOC Table -->
  <div class="table-wrap">
    <table id="iocTable">
      <thead>
        <tr>
          <th>IOC Type</th>
          <th>Value</th>
          <th>Risk</th>
          <th>VT Detections</th>
          <th>Malware Family</th>
        </tr>
      </thead>
      <tbody id="tableBody">
        {''.join(rows)}
      </tbody>
    </table>
    <div class="no-results" id="noResults">
      😶 No IOCs match your current filter. <a href="#" onclick="showAll()" style="color:#58a6ff;">Show all</a>
    </div>
  </div>

</div>

<div class="footer">
  Generated by <strong>Automated IOC Extractor v1.0</strong>
  &nbsp;|&nbsp; Digital Forensics Minor Project
</div>

<script>
  // ── State ──────────────────────────────────
  let activeType = null;   // currently selected card type
  let activeRisk = null;   // currently selected risk level

  const totalRows = document.querySelectorAll('#tableBody tr').length;

  // ── Filter by IOC Type (card click) ────────
  function filterByType(type) {{
    if (activeType === type) {{
      // clicking same card again → show all
      showAll();
      return;
    }}
    activeType = type;
    activeRisk = null;

    // Update card styles
    document.querySelectorAll('.card').forEach(c => {{
      if (c.dataset.type === type) {{
        c.classList.add('active');
        c.classList.remove('dimmed');
      }} else {{
        c.classList.remove('active');
        c.classList.add('dimmed');
      }}
    }});

    // Update show all button
    document.getElementById('showAllBtn').classList.remove('active');

    // Show filter badge
    const badge = document.getElementById('filterActive');
    badge.style.display = 'inline-block';
    badge.textContent = '✕  ' + type.toUpperCase();
    badge.onclick = showAll;

    applyFilters();
  }}

  // ── Filter by Risk Level ────────────────────
  function filterByRisk(risk) {{
    if (activeRisk === risk) {{
      showAll();
      return;
    }}
    activeRisk = risk;
    activeType = null;

    // Reset cards
    document.querySelectorAll('.card').forEach(c => {{
      c.classList.remove('active', 'dimmed');
    }});

    document.getElementById('showAllBtn').classList.remove('active');

    const badge = document.getElementById('filterActive');
    badge.style.display = 'inline-block';
    badge.textContent = '✕  Risk: ' + risk.toUpperCase();
    badge.onclick = showAll;

    applyFilters();
  }}

  // ── Show All ────────────────────────────────
  function showAll() {{
    activeType = null;
    activeRisk = null;
    document.getElementById('searchInput').value = '';

    // Reset cards
    document.querySelectorAll('.card').forEach(c => {{
      c.classList.remove('active', 'dimmed');
    }});

    document.getElementById('showAllBtn').classList.add('active');

    const badge = document.getElementById('filterActive');
    badge.style.display = 'none';
    badge.textContent = '';

    applyFilters();
    return false;
  }}

  // ── Core filter logic ───────────────────────
  function applyFilters() {{
    const search = document.getElementById('searchInput').value.toLowerCase().trim();
    const rows   = document.querySelectorAll('#tableBody tr');
    let visible  = 0;

    rows.forEach(row => {{
      const rowType = row.dataset.type || '';
      const text    = row.innerText.toLowerCase();

      const typeMatch = !activeType || rowType === activeType;
      const riskMatch = !activeRisk || text.includes(activeRisk.toLowerCase());
      const srchMatch = !search    || text.includes(search);

      if (typeMatch && riskMatch && srchMatch) {{
        row.classList.remove('hidden');
        visible++;
      }} else {{
        row.classList.add('hidden');
      }}
    }});

    // Update counter
    document.getElementById('visibleCount').textContent = visible;

    // Show/hide no-results message
    document.getElementById('noResults').style.display =
      visible === 0 ? 'block' : 'none';
  }}

  // ── Copy to clipboard ───────────────────────
  function copyVal(val) {{
    navigator.clipboard.writeText(val).then(() => {{
      const btn = event.target;
      btn.textContent = '✓';
      setTimeout(() => btn.textContent = 'copy', 1200);
    }});
  }}
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def export_all(iocs: dict, enriched: dict, output_dir: str, source: str = "") -> dict:
    """Export to all formats at once."""
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.join(output_dir, "ioc_report")
    return {
        "json":  export_json(iocs,  enriched, base + ".json",  source),
        "csv":   export_csv(iocs,   enriched, base + ".csv"),
        "stix":  export_stix(iocs,  enriched, base + ".stix.json", source),
        "html":  export_html(iocs,  enriched, base + ".html",  source),
    }