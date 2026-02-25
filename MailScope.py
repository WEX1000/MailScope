import sys
import json
from pathlib import Path

from app.analyzer import mail_analysis
from app.osintdata import gather_osint_data
from app.scoring import calculate_threat_score
from app.report import generate_markdown_report

RED    = "\033[31m"
YELLOW = "\033[33m"
ORANGE = "\033[38;5;208m"
RESET  = "\033[0m"

LOGO = YELLOW + """ __   __  _______  ___   ___      _______  _______  _______  _______  _______
|  |_|  ||   _   ||   | |   |    |       ||       ||       ||       ||       |
|       ||  |_|  ||   | |   |    |  _____||       ||   _   ||    _  ||    ___|
|       ||       ||   | |   |    | |_____ |       ||  | |  ||   |_| ||   |___
|       ||       ||   | |   |___ |_____  ||      _||  |_|  ||    ___||    ___|
| ||_|| ||   _   ||   | |       | _____| ||     |_ |       ||   |    |   |___
|_|   |_||__| |__||___| |_______||_______||_______||_______||___|    |_______|""" + RESET
LINE = "-" * 78

SCORE_COLORS = {
    "CRITICAL": RED,
    "HIGH":     RED,
    "MEDIUM":   ORANGE,
    "LOW":      YELLOW,
    "CLEAN":    "\033[32m",  # green
}


def print_threat_score(threat: dict):
    score = threat.get("score", 0)
    level = threat.get("level", "CLEAN")
    color = SCORE_COLORS.get(level, RESET)
    print("-" * 30 + " Threat Score " + "-" * 34)
    print(f"{color}Score: {score}/100  [{level}]{RESET}")
    for r in threat.get("reasons", []):
        print(f"  {color}! {r}{RESET}")


def main():
    vt_on      = False
    abuse_on   = False
    urlscan_on = False
    shodan_on  = False
    JSON_on    = False
    md_on      = False

    args = sys.argv[1:]

    if not args:
        print(LOGO)
        print(LINE)
        print(f"{RED}Missing argument, use -h{RESET}")
        return

    file_path = None
    i = 0
    while i < len(args):
        if args[i] == "-h":
            print(LOGO)
            print("  -h            show help")
            print("  -f <file>     path to .eml file")
            print("  -vt           enable VirusTotal")
            print("  -url          enable urlscan.io")
            print("  -abuse        enable AbuseIPDB")
            print("  -shodan       enable Shodan IP lookup")
            print("  -json         saves results to JSON file")
            print("  -md           saves results to Markdown report")
            print(LINE)
            return
        elif args[i] == "-f" and i + 1 < len(args):
            file_path = args[i + 1]
            i += 2
            continue
        elif args[i] == "-vt":
            vt_on = True; i += 1; continue
        elif args[i] == "-url":
            urlscan_on = True; i += 1; continue
        elif args[i] == "-abuse":
            abuse_on = True; i += 1; continue
        elif args[i] == "-shodan":
            shodan_on = True; i += 1; continue
        elif args[i] == "-json":
            JSON_on = True; i += 1; continue
        elif args[i] == "-md":
            md_on = True; i += 1; continue
        else:
            print(LOGO)
            print("Invalid argument, use -h")
            return

    if not file_path or not file_path.lower().endswith(".eml"):
        print(LOGO)
        print("Missing/invalid file path, use -h")
        return

    print(LOGO)
    print(LINE)
    print("File:", file_path)
    print(LINE)

    analysis_data = mail_analysis(file_path)

    if vt_on or abuse_on or urlscan_on or shodan_on:
        osint_tools_data = gather_osint_data(
            analysis_data,
            vt_on=vt_on,
            abuse_on=abuse_on,
            urlscan_on=urlscan_on,
            shodan_on=shodan_on,
        )
    else:
        osint_tools_data = {
            "vt_on":     vt_on,
            "abuse_on":  abuse_on,
            "urlscan_on": urlscan_on,
            "shodan_on": shodan_on,
        }

    threat = calculate_threat_score(analysis_data, osint_tools_data)

    print(f"Subject: {analysis_data['subject']}")
    print(LINE)
    print("Mail content:")
    print(analysis_data['content'])
    print(LINE)
    print("Basic info:")
    print(f"Date: {analysis_data['date']}")
    print(f"Sender domain: {analysis_data['sender_domain']}")
    print(f"Sender IP: {analysis_data['sender_ip']}")
    print(f"From: {analysis_data['sender_addr']}")
    print(f"Return-Path: {analysis_data['return_path']}")
    print(f"Recipients: {analysis_data['recipients']}")
    print(f"Message-ID: {analysis_data['message_id']}")
    print(f"User-Agent/X-Mailer: {analysis_data['user_agent']}")

    print("URLs:")
    for u in analysis_data["urls"]:
        print(f"  - {u}")

    print("Attachments:")
    susp_names = {s["name"] for s in analysis_data.get("suspicious_attachments", [])}
    for name, hash_val in (analysis_data["attachments_hashes"]).items():
        alert = f"  {RED}[!] SUSPICIOUS EXTENSION{RESET}" if name in susp_names else ""
        print(f"  - File name: {name}{alert}")
        print(f"    - SHA256 hash: {hash_val}")

    if analysis_data.get("suspicious_attachments"):
        print(f"{RED}[!] Suspicious attachments detected:{RESET}")
        for s in analysis_data["suspicious_attachments"]:
            print(f"    {RED}* {s['name']}  (extension: {s['ext']}){RESET}")

    if vt_on:
        print("-" * 34 + "VirusTotal" + "-" * 34)
        try:
            ip_rep = osint_tools_data['sender_ip_reputation']
            if ip_rep.get('score', 0) > 10:
                print(f"Sender IP reputation: {ip_rep['score']} - HIGH RISK!!!!")
            else:
                print(f"Sender IP reputation: {ip_rep['score']}")

            dom_rep = osint_tools_data['sender_domain_reputation']
            if dom_rep.get('score', 0) > 10:
                print(f"Sender domain reputation: {dom_rep['score']} - HIGH RISK!!!!")
            else:
                print(f"Sender domain reputation: {dom_rep['score']}")

            for name, hash_val in (analysis_data["attachments_hashes"]).items():
                h_rep = osint_tools_data[f'Hash reputation of {name} file']
                flag = " - HIGH RISK!!!!" if h_rep.get('score', 0) > 10 else ""
                print(f"File {name} reputation: {h_rep['score']}{flag}")
                print(f"  - File type: {h_rep.get('type')}")
                print(f"  - File size: {h_rep.get('size')}")
        except Exception:
            print("VirusTotal API data contains errors, check returned .JSON file")
            JSON_on = True

    if abuse_on:
        print("-" * 34 + "AbuseIPDB" + "-" * 35)
        try:
            ab = osint_tools_data['confidence_of_abuse']
            print(f"Confidence of abuse: {ab['confidence']}")
            print(f"No. of reports: {ab['reports']}")
            print(f"Country: {ab['country']}")
            print(f"ISP: {ab['isp']}")
            print(f"Usage: {ab['usage']}")
        except Exception:
            print("AbuseIPDB API data contains errors, check returned .JSON file")
            JSON_on = True

    if shodan_on:
        print("-" * 34 + " Shodan " + "-" * 36)
        try:
            sh = osint_tools_data['shodan_ip']
            if "error" in sh:
                print(f"Shodan error: {sh['error']}")
            else:
                print(f"Organization: {sh.get('org')}")
                print(f"ISP: {sh.get('isp')}")
                print(f"Country: {sh.get('country')}")
                ports = sh.get("ports", [])
                print(f"Open ports: {', '.join(str(p) for p in ports) if ports else 'none'}")
                tags = sh.get("tags", [])
                print(f"Tags: {', '.join(tags) if tags else 'none'}")
                vulns = sh.get("vulns", [])
                if vulns:
                    print(f"CVEs: {', '.join(vulns)}")
        except Exception:
            print("Shodan API data contains errors, check returned .JSON file")
            JSON_on = True

    if urlscan_on:
        print("-" * 34 + "URLScan" + "-" * 37)
        try:
            print(f"Sender domain scan: {osint_tools_data['sender_domain_scan']['result']}")
            for name in analysis_data["urls"]:
                print(f"URL '{name}' scan: {osint_tools_data[name]['result']}")
        except Exception:
            print("UrlScan API data contains errors, check returned .JSON file")
            JSON_on = True

    print_threat_score(threat)
    print(LINE)

    if JSON_on:
        results = {
            "analysis_data": analysis_data,
            "osint_tools_data": osint_tools_data,
            "threat_score": threat,
        }
        out = f"{Path(file_path).stem}.eml_Analysis.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"JSON saved: {out}")

    if md_on:
        out = generate_markdown_report(analysis_data, osint_tools_data, threat, file_path)
        print(f"Markdown report saved: {out}")


if __name__ == "__main__":
    main()
