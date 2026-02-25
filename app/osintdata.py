from urllib.parse import urlparse
import time

from .vt import vt_ip, vt_domain, vt_hash
from .abuseipdb import abuseipdb_ip
from .urlscan import urlscan_domain
from .shodan import shodan_ip


def gather_osint_data(
    analysis_data,
    vt_on=False,
    abuse_on=False,
    urlscan_on=False,
    shodan_on=False,
):
    osint_data = {
        "vt_on": vt_on,
        "abuse_on": abuse_on,
        "urlscan_on": urlscan_on,
        "shodan_on": shodan_on,
    }

    if vt_on:
        osint_data["sender_ip_reputation"] = vt_ip(analysis_data["sender_ip"])
        osint_data["sender_domain_reputation"] = vt_domain(analysis_data["sender_domain"])
        for name, file_hash in (analysis_data["attachments_hashes"]).items():
            osint_data[f"Hash reputation of {name} file"] = vt_hash(file_hash)

    if abuse_on:
        osint_data["confidence_of_abuse"] = abuseipdb_ip(analysis_data["sender_ip"])

    if shodan_on:
        osint_data["shodan_ip"] = shodan_ip(analysis_data["sender_ip"])

    if urlscan_on:
        osint_data["sender_domain_scan"] = urlscan_domain(analysis_data["sender_domain"])
        time.sleep(5)
        for u in analysis_data["urls"]:
            p = urlparse(u)
            d = (p.netloc or p.path).lower()
            if d.startswith("www."):
                d = d[4:]
            osint_data[u] = urlscan_domain(d)
            time.sleep(5)

    return osint_data
