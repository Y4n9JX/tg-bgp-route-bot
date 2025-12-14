
import requests



def _bgptools_ip(ip: str, ua: str, timeout: int = 15) -> dict | None:

    url = f"https://bgp.tools/api/ip/{ip}"

    r = requests.get(url, headers={"User-Agent": ua}, timeout=timeout)

    if r.status_code != 200:

        return None

    j = r.json()

    if not j or "asn" not in j:

        return None

    return {

        "source": "bgp.tools",

        "asn": j.get("asn"),

        "asn_name": j.get("asn_name"),

        "prefix": j.get("prefix"),

    }



def _ripe_ip(ip: str, ua: str, timeout: int = 15) -> dict | None:

    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"

    r = requests.get(url, headers={"User-Agent": ua}, timeout=timeout)

    if r.status_code != 200:

        return None

    j = r.json()

    data = j.get("data", {})

    asns = data.get("asns", [])

    if not asns:

        return None



    a = asns[0]

    return {

        "source": "ripe",

        "asn": a.get("asn"),

        "asn_name": a.get("holder"),

        "prefix": data.get("prefix"),

    }



def lookup_ip_to_asn(ip: str, user_agent: str, timeout: int = 20) -> dict | None:

    ua = user_agent or "bgp-route-bot - contact: none"



    # 1) 先试 bgp.tools

    r = _bgptools_ip(ip, ua, timeout)

    if r:

        return r



    # 2) 再试 RIPE（兜底，成功率极高）

    r = _ripe_ip(ip, ua, timeout)

    if r:

        return r



    return None

