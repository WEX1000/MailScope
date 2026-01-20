import sys
import json
from pathlib import Path

from app.analyzer import mail_analysis
from app.osintdata import gather_osint_data

RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

LOGO = YELLOW + """ __   __  _______  ___   ___      _______  _______  _______  _______  _______ 
|  |_|  ||   _   ||   | |   |    |       ||       ||       ||       ||       |
|       ||  |_|  ||   | |   |    |  _____||       ||   _   ||    _  ||    ___|
|       ||       ||   | |   |    | |_____ |       ||  | |  ||   |_| ||   |___ 
|       ||       ||   | |   |___ |_____  ||      _||  |_|  ||    ___||    ___|
| ||_|| ||   _   ||   | |       | _____| ||     |_ |       ||   |    |   |___ 
|_|   |_||__| |__||___| |_______||_______||_______||_______||___|    |_______|""" + RESET
LINE = "-" * 78
def main():
    vt_on = False
    abuse_on = False
    urlscan_on = False
    JSON_on = False
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
            print("  -json         saves results to JSON file")
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
        elif args[i] == "-json":
            JSON_on = True; i += 1; continue
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

    if vt_on or abuse_on or urlscan_on:
        osint_tools_data = gather_osint_data(analysis_data, vt_on=vt_on, abuse_on=abuse_on, urlscan_on=urlscan_on)
    else:
        osint_tools_data = {
            "vt_on" : vt_on,
            "abuse_on" : abuse_on,
            "urlscan_on" : urlscan_on
        }
    
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
    
    print("Attachements:")
    for name, hash in (analysis_data["attachments_hashes"]).items():
        print(f"  - File name: {name}")
        print(f"    - SHA256 hash: {hash}")
    
    if vt_on:
        print("-" * 34 + "VirusTotal" + "-" * 34)
        try:
            if osint_tools_data['sender_ip_reputation']['score'] > 10:
                print(f"Sender IP reputation: {osint_tools_data['sender_ip_reputation']['score']} - HIGH RISK!!!!")
            else:
                print(f"Sender IP reputation: {osint_tools_data['sender_ip_reputation']['score']}")

            if osint_tools_data['sender_domain_reputation']['score'] > 10:
                print(f"Sender domain reputation: {osint_tools_data['sender_domain_reputation']['score']} - HIGH RISK!!!!") 
            else:
                print(f"Sender domain reputation: {osint_tools_data['sender_domain_reputation']['score']}") 

            for name, hash in (analysis_data["attachments_hashes"]).items():
                if osint_tools_data[f'Hash reputation of {name} file']['score'] > 10:
                    print(f"File {name} reputation: {osint_tools_data[f'Hash reputation of {name} file']['score']} - HIGH RISK!!!!")
                    print(f"  - File type: {osint_tools_data[f'Hash reputation of {name} file']['type']}")
                    print(f"  - File size: {osint_tools_data[f'Hash reputation of {name} file']['size']}")
                else:
                    print(f"File {name} reputation: {osint_tools_data[f'Hash reputation of {name} file']['score']}")
                    print(f"  - File type: {osint_tools_data[f'Hash reputation of {name} file']['type']}")
                    print(f"  - File size: {osint_tools_data[f'Hash reputation of {name} file']['size']}")
        except:
            print("VirusTotal API data contains errors, check returned .JSON file")
            JSON_on = True
    
    if abuse_on:
        print("-" * 34 + "AbuseIPDB" + "-" * 35)
        try:
            print(f"Confidence of abuse: {osint_tools_data['confidence_of_abuse']['confidence']}")
            print(f"No. of reports: {osint_tools_data['confidence_of_abuse']['reports']}")
            print(f"Country: {osint_tools_data['confidence_of_abuse']['country']}")
            print(f"ISP: {osint_tools_data['confidence_of_abuse']['isp']}")
            print(f"Usage: {osint_tools_data['confidence_of_abuse']['usage']}")
        except:
            print("AbuseIPDB API data contains errors, check returned .JSON file")
            JSON_on = True

    if urlscan_on:
        print("-" * 34 + "URLScan" + "-" * 37)
        try:
            print(f"Sender domain scan: {osint_tools_data['sender_domain_scan']['result']}")
            for name in analysis_data["urls"]:
                print(f"URL '{name}' scan: {osint_tools_data[name]['result']}")
        except:
            print("UrlScan API data contains errors, check returned .JSON file")
            JSON_on = True
    
    print(LINE)

    if JSON_on:
        results = {
            "analysis_data" : analysis_data,
            "osint_tools_data" : osint_tools_data
        }
        with open(f"{Path(file_path).stem}.eml_Analysis.json", "w",  encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()

#print(json.dumps(analysis_data, indent=2, ensure_ascii=False))
#print(json.dumps(osint_tools_data, indent=2, ensure_ascii=False))