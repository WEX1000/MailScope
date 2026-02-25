import requests
from .config import SHODAN_API_KEY


def shodan_ip(ip: str):
    if not ip:
        return None
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY_not_set"}

    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        return {"error": f"shodan_request_failed: {e}"}

    if r.status_code == 401:
        return {"error": "shodan_401_unauthorized"}
    if r.status_code == 404:
        return {"error": "shodan_404_no_info"}
    if r.status_code == 429:
        return {"error": "shodan_429_rate_limited"}
    if not r.ok:
        return {"error": f"shodan_{r.status_code}"}

    data = r.json()
    return {
        "org": data.get("org"),
        "isp": data.get("isp"),
        "country": data.get("country_name"),
        "country_code": data.get("country_code"),
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "tags": data.get("tags", []),
        "vulns": list(data.get("vulns", {}).keys()),
        "last_update": data.get("last_update"),
    }
