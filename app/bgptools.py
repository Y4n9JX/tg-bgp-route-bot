import os
import csv
import io
import requests
from tenacity import retry, stop_after_attempt, wait_fixed

ASNS_CSV_URL = "https://bgp.tools/asns.csv"

def _ua() -> str:
    ua = os.getenv("HTTP_USER_AGENT", "").strip()
    return ua or "bgp-route-bot contact: chatgp1@axonmail.de"

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def fetch_asn_name_map() -> dict[int, str]:
    r = requests.get(ASNS_CSV_URL, headers={"User-Agent": _ua()}, timeout=30)
    r.raise_for_status()

    mp: dict[int, str] = {}
    f = io.StringIO(r.text)
    reader = csv.DictReader(f)
    for row in reader:
        asn_str = (row.get("asn") or "").strip().upper()
        name = (row.get("name") or "").strip()
        if asn_str.startswith("AS"):
            try:
                mp[int(asn_str[2:])] = name
            except ValueError:
                pass
    return mp
