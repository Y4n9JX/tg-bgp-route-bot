
import requests



def fetch_prefixes_from_bgptools_table(asn: int, user_agent: str, timeout: int = 60) -> list[str]:

    """

    bgp.tools/table.txt 每行：<CIDR> <ASN>

    官方 KB 明确给机器用，并建议缓存。:contentReference[oaicite:4]{index=4}

    """

    url = "https://bgp.tools/table.txt"

    headers = {"User-Agent": user_agent}

    r = requests.get(url, headers=headers, timeout=timeout, stream=True)

    r.raise_for_status()



    prefixes: list[str] = []

    suffix = f" {asn}"

    for raw in r.iter_lines(decode_unicode=True):

        if not raw:

            continue

        # 例：1.2.3.0/24 56040

        if raw.endswith(suffix):

            pfx = raw.split()[0].strip()

            prefixes.append(pfx)



    # 去重保持顺序

    seen = set()

    out = []

    for p in prefixes:

        if p not in seen:

            seen.add(p)

            out.append(p)

    return out

