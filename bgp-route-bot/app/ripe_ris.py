
import requests

import re



_DIGITS = re.compile(r"\d+")



def _to_as_path(obj) -> list[int] | None:

    """

    尽量兼容 ris-peerings 返回的 routes 元素结构：

    - 可能是 dict，里面有 as_path/path 字段

    - 可能是字符串（包含 ASN）

    - 可能直接是列表

    """

    if obj is None:

        return None



    if isinstance(obj, list):

        out = []

        for x in obj:

            if isinstance(x, int):

                out.append(x)

            elif isinstance(x, str) and x.isdigit():

                out.append(int(x))

        return out or None



    if isinstance(obj, str):

        nums = _DIGITS.findall(obj)

        return [int(x) for x in nums] if nums else None



    if isinstance(obj, dict):

        for k in ("as_path", "aspath", "path", "as-path"):

            if k in obj:

                return _to_as_path(obj.get(k))

        # 兜底：把整个 dict 转成字符串抓数字

        nums = _DIGITS.findall(str(obj))

        return [int(x) for x in nums] if nums else None



    nums = _DIGITS.findall(str(obj))

    return [int(x) for x in nums] if nums else None





def fetch_ris_aspaths_for_origin(asn: int, user_agent: str, timeout: int = 30) -> list[list[int]]:

    """

    RIPEstat RIS Peerings:

    https://stat.ripe.net/data/ris-peerings/data.json?resource=ASxxxx

    文档说明 routes 字段包含 AS-path 列表。:contentReference[oaicite:2]{index=2}

    """

    url = f"https://stat.ripe.net/data/ris-peerings/data.json?resource=AS{asn}"

    headers = {"User-Agent": user_agent or "bgp-route-bot - contact: none"}

    r = requests.get(url, headers=headers, timeout=timeout)

    r.raise_for_status()

    j = r.json()



    data = j.get("data", {})

    peerings = data.get("peerings", []) or []



    out: list[list[int]] = []

    for probe in peerings:

        for peer in probe.get("peers", []) or []:

            for route in peer.get("routes", []) or []:

                p = _to_as_path(route)

                if p:

                    # 只保留“以目标 ASN 结尾”的路径（origin）

                    if p and p[-1] == asn:

                        out.append(p)

    return out

