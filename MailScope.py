import sys
import json
from pathlib import Path

from app.analyzer import mail_analysis
from app.osintdata import gather_osint_data
from app.scoring import calculate_threat_score
from app.report import generate_markdown_report

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED    = "\033[31m"
YELLOW = "\033[33m"
ORANGE = "\033[38;5;208m"
GREEN  = "\033[32m"
RESET  = "\033[0m"

SCORE_COLOURS = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   ORANGE,
    "LOW":      YELLOW,
    "CLEAN":    GREEN,
}

LOGO = YELLOW + """\
 __   __  _______  ___   ___      _______  _______  _______  _______  _______
|  |_|  ||   _   ||   | |   |    |       ||       ||       ||       ||       |
|       ||  |_|  ||   | |   |    |  _____||       ||   _   ||    _  ||    ___|
|       ||       ||   | |   |    | |_____ |       ||  | |  ||   |_| ||   |___
|       ||       ||   | |   |___ |_____  ||      _||  |_|  ||    ___||    ___|
| ||_|| ||   _   ||   | |       | _____| ||     |_ |       ||   |    |   |___
|_|   |_||__| |__||___| |_______||_______||_______||_______||___|    |_______|""" + RESET

LINE = "-" * 78

HELP_TEXT = """\
  -h            show help
  -f <file>     path to .eml file
  -vt           enable VirusTotal
  -url          enable urlscan.io
  -abuse        enable AbuseIPDB
  -shodan       enable Shodan IP lookup
  -json         save results to JSON file
  -md           save results to Markdown report"""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _section(title: str) -> str:
    """Return a 78-char section divider with a centred title."""
    inner = f" {title} "
    left  = (78 - len(inner)) // 2
    right = 78 - len(inner) - left
    return "-" * left + inner + "-" * right


# ── Argument parsing ─────────────────────────────────────────────────────────

class Args:
    __slots__ = ("file_path", "vt", "abuse", "urlscan", "shodan", "json", "md")

    def __init__(self):
        self.file_path: str | None = None
        self.vt      = False
        self.abuse   = False
        self.urlscan = False
        self.shodan  = False
        self.json    = False
        self.md      = False


def _parse_args(argv: list[str]) -> Args | None:
    """Parse sys.argv[1:]. Returns None when execution should stop (help/error)."""
    if not argv:
        print(LOGO)
        print(LINE)
        print(f"{RED}Missing argument, use -h{RESET}")
        return None

    args = Args()
    i = 0
    while i < len(argv):
        match argv[i]:
            case "-h":
                print(LOGO)
                print(HELP_TEXT)
                print(LINE)
                return None
            case "-f":
                if i + 1 >= len(argv):
                    print(LOGO)
                    print("Missing value for -f, use -h")
                    return None
                args.file_path = argv[i + 1]
                i += 2
            case "-vt":    args.vt      = True; i += 1
            case "-url":   args.urlscan = True; i += 1
            case "-abuse": args.abuse   = True; i += 1
            case "-shodan":args.shodan  = True; i += 1
            case "-json":  args.json    = True; i += 1
            case "-md":    args.md      = True; i += 1
            case _:
                print(LOGO)
                print(f"Unknown argument '{argv[i]}', use -h")
                return None

    if not args.file_path or not args.file_path.lower().endswith(".eml"):
        print(LOGO)
        print("Missing/invalid file path, use -h")
        return None

    return args


# ── Section display functions ─────────────────────────────────────────────────

def _display_email_info(analysis_data: dict) -> None:
    print(f"Subject: {analysis_data['subject']}")
    print(LINE)
    print("Mail content:")
    print(analysis_data["content"])
    print(LINE)
    print("Basic info:")
    for label, key in (
        ("Date",                "date"),
        ("Sender domain",       "sender_domain"),
        ("Sender IP",           "sender_ip"),
        ("From",                "sender_addr"),
        ("Return-Path",         "return_path"),
        ("Message-ID",          "message_id"),
        ("User-Agent/X-Mailer", "user_agent"),
    ):
        print(f"{label}: {analysis_data[key]}")
    print(f"Recipients: {analysis_data['recipients']}")


def _display_urls(urls: list[str]) -> None:
    print("URLs:")
    for u in urls:
        print(f"  - {u}")


def _display_attachments(analysis_data: dict) -> None:
    susp_names = {s["name"] for s in analysis_data.get("suspicious_attachments", [])}
    print("Attachments:")
    for name, sha256 in analysis_data["attachments_hashes"].items():
        alert = f"  {RED}[!] SUSPICIOUS EXTENSION{RESET}" if name in susp_names else ""
        print(f"  - {name}{alert}")
        print(f"    SHA256: {sha256}")

    if analysis_data.get("suspicious_attachments"):
        print(f"{RED}[!] Suspicious attachments:{RESET}")
        for s in analysis_data["suspicious_attachments"]:
            print(f"    {RED}* {s['name']}  ({s['ext']}){RESET}")


def _display_vt(analysis_data: dict, osint_data: dict) -> bool:
    """Prints VirusTotal results. Returns True if an error occurred."""
    print(_section("VirusTotal"))
    try:
        ip_rep  = osint_data["sender_ip_reputation"]
        dom_rep = osint_data["sender_domain_reputation"]

        for label, rep in (("Sender IP reputation", ip_rep), ("Sender domain reputation", dom_rep)):
            flag = " - HIGH RISK!!!!" if rep.get("score", 0) > 10 else ""
            print(f"{label}: {rep['score']}{flag}")

        for name in analysis_data["attachments_hashes"]:
            h = osint_data[f"Hash reputation of {name} file"]
            flag = " - HIGH RISK!!!!" if h.get("score", 0) > 10 else ""
            print(f"File '{name}' reputation: {h['score']}{flag}")
            print(f"  - Type: {h.get('type')}  Size: {h.get('size')} bytes")

        return False
    except Exception:
        print("VirusTotal API data contains errors – check JSON output")
        return True


def _display_abuse(osint_data: dict) -> bool:
    """Prints AbuseIPDB results. Returns True if an error occurred."""
    print(_section("AbuseIPDB"))
    try:
        ab = osint_data["confidence_of_abuse"]
        for label, field in (
            ("Confidence of abuse", "confidence"),
            ("Reports (90 days)",   "reports"),
            ("Country",             "country"),
            ("ISP",                 "isp"),
            ("Usage type",          "usage"),
        ):
            print(f"{label}: {ab[field]}")
        return False
    except Exception:
        print("AbuseIPDB API data contains errors – check JSON output")
        return True


def _display_shodan(osint_data: dict) -> bool:
    """Prints Shodan results. Returns True if an error occurred."""
    print(_section("Shodan"))
    try:
        sh = osint_data["shodan_ip"]
        if "error" in sh:
            print(f"Error: {sh['error']}")
            return False
        print(f"Organization : {sh.get('org')}")
        print(f"ISP          : {sh.get('isp')}")
        print(f"Country      : {sh.get('country')}")
        ports = sh.get("ports", [])
        print(f"Open ports   : {', '.join(str(p) for p in ports) or 'none'}")
        tags  = sh.get("tags", [])
        print(f"Tags         : {', '.join(tags) or 'none'}")
        vulns = sh.get("vulns", [])
        if vulns:
            print(f"CVEs         : {', '.join(vulns)}")
        return False
    except Exception:
        print("Shodan API data contains errors – check JSON output")
        return True


def _display_urlscan(analysis_data: dict, osint_data: dict) -> bool:
    """Prints URLScan results. Returns True if an error occurred."""
    print(_section("URLScan.io"))
    try:
        print(f"Sender domain: {osint_data['sender_domain_scan']['result']}")
        for u in analysis_data["urls"]:
            print(f"URL '{u}': {osint_data[u]['result']}")
        return False
    except Exception:
        print("URLScan API data contains errors – check JSON output")
        return True


def _display_threat_score(threat: dict) -> None:
    score  = threat.get("score", 0)
    level  = threat.get("level", "CLEAN")
    colour = SCORE_COLOURS.get(level, RESET)
    print(_section("Threat Score"))
    print(f"{colour}Score: {score}/100  [{level}]{RESET}")
    for reason in threat.get("reasons", []):
        print(f"  {colour}! {reason}{RESET}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args(sys.argv[1:])
    if args is None:
        return

    print(LOGO)
    print(LINE)
    print(f"File: {args.file_path}")
    print(LINE)

    analysis_data = mail_analysis(args.file_path)

    any_osint = args.vt or args.abuse or args.urlscan or args.shodan
    if any_osint:
        osint_data = gather_osint_data(
            analysis_data,
            vt_on=args.vt,
            abuse_on=args.abuse,
            urlscan_on=args.urlscan,
            shodan_on=args.shodan,
        )
    else:
        osint_data = {
            "vt_on": False, "abuse_on": False,
            "urlscan_on": False, "shodan_on": False,
        }

    threat = calculate_threat_score(analysis_data, osint_data)

    _display_email_info(analysis_data)
    _display_urls(analysis_data["urls"])
    _display_attachments(analysis_data)

    had_error = False
    if args.vt:     had_error |= _display_vt(analysis_data, osint_data)
    if args.abuse:  had_error |= _display_abuse(osint_data)
    if args.shodan: had_error |= _display_shodan(osint_data)
    if args.urlscan:had_error |= _display_urlscan(analysis_data, osint_data)

    _display_threat_score(threat)
    print(LINE)

    if args.json or had_error:
        results = {
            "analysis_data":  analysis_data,
            "osint_data":     osint_data,
            "threat_score":   threat,
        }
        out = f"{Path(args.file_path).stem}.eml_Analysis.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"JSON saved: {out}")

    if args.md:
        out = generate_markdown_report(analysis_data, osint_data, threat, args.file_path)
        print(f"Markdown report saved: {out}")


if __name__ == "__main__":
    main()
