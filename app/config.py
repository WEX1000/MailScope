def load_keys(path="API.key"):
    keys = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            keys[k.strip()] = v.strip().strip('"').strip("'")
    return keys

KEYS = load_keys("API.key")
VT_API_KEY = KEYS.get("VT_API_KEY", "")
URLSCAN_API_KEY = KEYS.get("URLSCAN_API_KEY", "")
ABUSEIPDB_API_KEY = KEYS.get("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY = KEYS.get("SHODAN_API_KEY", "")