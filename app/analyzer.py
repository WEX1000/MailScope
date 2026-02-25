from email.parser import BytesParser
from email.policy import default
from email.utils import parseaddr, getaddresses
import re
import ipaddress
import hashlib
from pathlib import Path

from .utils import URL_REGEX, dedupe

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".ps2", ".psm1", ".psd1", ".hta", ".jar",
    ".msi", ".dll", ".lnk", ".reg", ".inf", ".msc",
    ".cpl", ".sys", ".drv", ".ocx", ".cab",
    ".iso", ".img", ".dmg", ".apk", ".ipa",
}

def mail_analysis(path: str):
    with open(path, "rb") as f:
        msg = BytesParser(policy=default).parse(f)

    sender_addr = parseaddr(msg.get("From", ""))[1]
    sender_domain = sender_addr.split("@", 1)[1] if "@" in sender_addr else None
    return_path = parseaddr(msg.get("Return-Path", ""))[1]
    date = msg.get("Date")
    message_id = msg.get("Message-ID")
    user_agent = msg.get("User-Agent") or msg.get("X-Mailer")
    subject = msg.get("Subject", "")

    recipients = []
    for hdr in ("To", "Cc", "Bcc"):
        recipients += [addr for _, addr in getaddresses(msg.get_all(hdr, [])) if addr]

    sender_ip = None
    for h in reversed(msg.get_all("Received", [])):
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", h):
            try:
                if ipaddress.ip_address(ip).is_global:
                    sender_ip = ip
                    break
            except ValueError:
                pass
        if sender_ip:
            break

    body_html = msg.get_body(preferencelist=("html", "plain"))
    urls = dedupe(URL_REGEX.findall(body_html.get_content())) if body_html else []

    body_plain = msg.get_body(preferencelist=("plain", "html"))
    content = body_plain.get_content() if body_plain else ""

    attachments_hashes = {}
    suspicious_attachments = []
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue

        data = part.get_payload(decode=True)
        if not data:
            continue

        name = part.get_filename() or "brak_nazwy"
        sha256 = hashlib.sha256(data).hexdigest()
        attachments_hashes[name] = sha256

        ext = Path(name).suffix.lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            suspicious_attachments.append({"name": name, "ext": ext})

    return {
        "subject" : subject,
        "content" : content,
        "date" : date,
        "sender_domain" : sender_domain,
        "sender_ip" : sender_ip,
        "sender_addr" : sender_addr,
        "return_path" : return_path,
        "recipients" : recipients,
        "message_id" : message_id,
        "user_agent" : user_agent,
        "urls" : urls,
        "attachments_hashes" : attachments_hashes,
        "suspicious_attachments" : suspicious_attachments,
    }
