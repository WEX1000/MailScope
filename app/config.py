import sys


def load_keys(path: str = "API.key") -> dict:
    keys: dict = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        print(f"[config] Warning: '{path}' not found – API keys will be empty.", file=sys.stderr)
    return keys


_KEYS = load_keys("API.key")

VT_API_KEY       = _KEYS.get("VT_API_KEY",       "")
URLSCAN_API_KEY  = _KEYS.get("URLSCAN_API_KEY",  "")
ABUSEIPDB_API_KEY= _KEYS.get("ABUSEIPDB_API_KEY","")
SHODAN_API_KEY   = _KEYS.get("SHODAN_API_KEY",   "")
