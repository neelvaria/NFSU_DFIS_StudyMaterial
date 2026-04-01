#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          AUTOMATED IOC EXTRACTOR  v1.0                       ║
║          Digital Forensics                                   ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  python ioc_extractor.py --file report.txt
  python ioc_extractor.py --file report.txt --vt-key YOUR_API_KEY
  python ioc_extractor.py --text "malware connects to 192.168.1.1"
  python ioc_extractor.py --file report.txt --output ./results
  python ioc_extractor.py --file report.txt --format json
  python ioc_extractor.py --stdin   (pipe text from stdin)
"""

import sys
import os
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.extractor  import extract_iocs, get_ioc_summary, get_total_count
from modules.parser     import parse_file, parse_text
from modules.enrichment import enrich_iocs
from modules.exporter   import export_all, export_json, export_csv, export_stix, export_html
from modules.display    import (
    print_banner, print_section, print_ioc_table,
    print_summary, print_enrichment, print_export_paths,
    print_progress, print_error, print_success, print_info,
    prompt_api_key, c, BRIGHT_CYAN, BRIGHT_GREEN, DIM, BOLD
)


# ─────────────────────────────────────────────
#  Argument Parser
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc_extractor",
        description="Automated IOC Extractor — Digital Forensics Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ioc_extractor.py --file threat_report.txt
  python ioc_extractor.py --file report.txt --vt-key YOUR_KEY
  python ioc_extractor.py --text "connects to evil.com hash abc123"
  python ioc_extractor.py --file report.html --format csv
  cat report.txt | python ioc_extractor.py --stdin
        """
    )

    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--file", "-f",
        metavar="PATH",
        help="Path to threat intel report file (.txt .log .html .json .csv .md)"
    )
    input_group.add_argument(
        "--text", "-t",
        metavar="TEXT",
        help="Raw text string to extract IOCs from"
    )
    input_group.add_argument(
        "--stdin",
        action="store_true",
        help="Read text from standard input (pipe)"
    )

    # Enrichment
    parser.add_argument(
        "--vt-key", "-k",
        metavar="API_KEY",
        default="072e67d28b4659b299a83a326bc8bc1d047d3c1ca5931ecde02f0cf1bbd63118",
        help="VirusTotal API key for enrichment (free at virustotal.com)"
    )
    parser.add_argument(
        "--prompt-key",
        action="store_true",
        help="Interactively prompt for VirusTotal API key"
    )
    parser.add_argument(
        "--vt-limit",
        type=int,
        default=99999,
        metavar="N",
        help="Max IOCs per type to enrich (default: 5, free API limit)"
    )

    # Output
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default=None,
        help="Output directory for exported files (auto-named if not specified)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv", "stix", "html", "all"],
        default="all",
        help="Export format (default: all)"
    )

    # Filters
    parser.add_argument(
        "--include-private-ips",
        action="store_true",
        help="Include private/reserved IP addresses (filtered by default)"
    )
    parser.add_argument(
        "--types",
        metavar="TYPE",
        nargs="+",
        help="Only extract specific IOC types (e.g. --types ipv4 domain sha256)"
    )

    # Display
    parser.add_argument(
        "--no-table",
        action="store_true",
        help="Skip printing the full IOC table to terminal"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output — only print extracted IOC values"
    )

    return parser


# ─────────────────────────────────────────────
#  Core Pipeline
# ─────────────────────────────────────────────

def run(args) -> int:
    """Main extraction pipeline. Returns exit code."""

    if not args.quiet:
        print_banner()

    # ── Step 1: Read Input ──────────────────────────────────────
    source_label = ""
    try:
        if args.file:
            if not args.quiet:
                print_info(f"Reading file: {args.file}")
            text = parse_file(args.file)
            source_label = os.path.basename(args.file)

        elif args.text:
            text = parse_text(args.text)
            source_label = "inline-text"

        elif args.stdin:
            if not args.quiet:
                print_info("Reading from stdin...")
            text = sys.stdin.read()
            source_label = "stdin"

    except FileNotFoundError as e:
        print_error(str(e))
        return 1
    except Exception as e:
        print_error(f"Failed to read input: {e}")
        return 1

    if not text.strip():
        print_error("Input text is empty.")
        return 1

    if not args.quiet:
        print_success(f"Input loaded — {len(text):,} characters")

    # ── Step 2: Extract IOCs ────────────────────────────────────
    if not args.quiet:
        print_section("EXTRACTING IOCs")

    iocs = extract_iocs(text, include_private_ips=args.include_private_ips)

    # Filter to requested types if specified
    if args.types:
        iocs = {k: v for k, v in iocs.items() if k in args.types}

    total = get_total_count(iocs)

    if args.quiet:
        # Quiet mode: just print values
        try:
            for ioc_type, values in sorted(iocs.items()):
                for val in values:
                    print(f"{ioc_type}\t{val}")
        except BrokenPipeError:
            pass
        return 0

    if total == 0:
        print_info("No IOCs found in the provided text.")
        return 0

    # Print summary
    print_summary(iocs)

    # Print full table
    if not args.no_table:
        print_section("EXTRACTED IOCs")
        print_ioc_table(iocs)

    # ── Step 3: Enrich with VirusTotal ──────────────────────────
    enriched = {}
    api_key = args.vt_key or ""

    if args.prompt_key and not api_key:
        api_key = prompt_api_key()

    if api_key:
        print_section("VIRUSTOTAL ENRICHMENT")
        print_info(f"Enriching up to {args.vt_limit} IOCs per type...")

        try:
            enriched = enrich_iocs(iocs, api_key, max_per_type=args.vt_limit)
            print_enrichment(enriched)
        except Exception as e:
            print_error(f"Enrichment failed: {e}")
            enriched = {}
    else:
        print_info("No VT API key — skipping enrichment. Use --vt-key to enable.")

    # ── Auto-generate output folder name ──────────────────────
    if args.output is None:
        from datetime import datetime
        import re as _re
        if args.file:
            base_name = os.path.splitext(os.path.basename(args.file))[0]
            base_name = _re.sub(r"[^\w\-]", "_", base_name)
        else:
            base_name = "inline_text"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = os.path.join(".", "reports", f"{base_name}_{timestamp}")

    if not args.quiet:
        print_info(f"Output folder: {args.output}")

    # ── Step 4: Export ────────────────────────────────────────
    print_section("EXPORTING RESULTS")

    try:
        if args.format == "all":
            paths = export_all(iocs, enriched, args.output, source_label)
        elif args.format == "json":
            path = export_json(iocs, enriched,
                               os.path.join(args.output, "ioc_report.json"), source_label)
            paths = {"json": path}
        elif args.format == "csv":
            path = export_csv(iocs, enriched,
                              os.path.join(args.output, "ioc_report.csv"))
            paths = {"csv": path}
        elif args.format == "stix":
            path = export_stix(iocs, enriched,
                               os.path.join(args.output, "ioc_report.stix.json"), source_label)
            paths = {"stix": path}
        elif args.format == "html":
            path = export_html(iocs, enriched,
                               os.path.join(args.output, "ioc_report.html"), source_label)
            paths = {"html": path}

        print_export_paths(paths)

    except Exception as e:
        print_error(f"Export failed: {e}")
        return 1

    # ── Done ──────────────────────────────────────────────────
    print(f"\n  {c('═' * 62, DIM)}")
    print(f"  {c('✔ DONE', BRIGHT_GREEN, BOLD)}  "
          f"Extracted {c(str(total), BRIGHT_CYAN, BOLD)} IOCs "
          f"from {c(source_label, BRIGHT_CYAN)}")
    print(f"  {c('Output saved to:', DIM)} {c(args.output, BRIGHT_CYAN)}")
    print(f"  {c('═' * 62, DIM)}\n")

    return 0


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run(args))