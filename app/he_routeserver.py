
import telnetlib

import re

from tenacity import retry, stop_after_attempt, wait_fixed



PROMPT_RE = re.compile(rb"[>#] ?$")

MORE_RE = re.compile(rb"--More--|<--- More --->", re.IGNORECASE)



# 粗略识别 next-hop（IPv4/IPv6，不带 /）

NEXTHOP_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]+)$")





def _read_until_prompt(tn: telnetlib.Telnet, timeout: int = 180) -> str:

    buf = b""

    while True:

        chunk = tn.read_until(b"\n", timeout=timeout)

        if not chunk:

            break

        buf += chunk



        if MORE_RE.search(buf[-200:]):

            tn.write(b" ")

            continue



        lines = buf.splitlines()

        if lines and PROMPT_RE.search(lines[-1]):

            break

    return buf.decode(errors="ignore")





def _login_and_setup(tn: telnetlib.Telnet) -> None:

    banner = tn.read_until(b":", timeout=5)

    if b"Username" in banner or b"login" in banner.lower():

        tn.write(b"rviews\n")

        pw = tn.read_until(b":", timeout=5)

        if b"Password" in pw:

            tn.write(b"rviews\n")



    _read_until_prompt(tn, timeout=10)



    tn.write(b"terminal length 0\n")

    _read_until_prompt(tn, timeout=5)

    tn.write(b"terminal width 0\n")

    _read_until_prompt(tn, timeout=5)





def _clean_prefix(tok: str) -> str:

    # 处理 "*>1.2.3.0/24" 或 "*> 1.2.3.0/24"

    return tok.strip().lstrip("*>").strip()





def _looks_like_prefix(tok: str) -> bool:

    t = _clean_prefix(tok)

    return "/" in t and (("." in t) or (":" in t))





def _looks_like_nexthop(tok: str) -> bool:

    t = tok.strip()

    return bool(NEXTHOP_RE.match(t)) and "/" not in t and (("." in t) or (":" in t))





def _parse_line_prefix_aspath(line: str) -> tuple[str, list[int]] | None:

    s = line.strip()

    if not s:

        return None



    # 过滤表头/提示/错误

    if s.startswith((

        "BGP routing table",

        "Status codes",

        "Origin codes",

        "Network",

        "Path",

        "Total number",

        "Displayed",

        "route-server",

        "show ",

        "%",

    )):

        return None



    parts = s.split()

    if len(parts) < 3:

        return None



    # 找 prefix（允许 token 前粘着 "*>")

    pfx_i = None

    for i in range(min(len(parts), 15)):

        if _looks_like_prefix(parts[i]):

            pfx_i = i

            break

    if pfx_i is None:

        return None



    prefix = _clean_prefix(parts[pfx_i])

    if "/" not in prefix:

        return None



    # 找 next-hop：从 prefix 后面往后 1~6 个 token 里找一个像 IP 的

    nh_i = None

    for j in range(pfx_i + 1, min(pfx_i + 7, len(parts))):

        if _looks_like_nexthop(parts[j]):

            nh_i = j

            break

    if nh_i is None:

        return None



    tail = parts[nh_i + 1 :]



    # 去掉末尾 origin code i/e/?

    if tail and tail[-1] in {"i", "e", "?"}:

        tail = tail[:-1]



    # 跳过 metric/locpref/weight：最多 3 个纯数字列

    k = 0

    skipped = 0

    while k < len(tail) and skipped < 3 and tail[k].isdigit():

        k += 1

        skipped += 1



    # 剩余纯数字 token 作为 AS_PATH

    as_path: list[int] = []

    for tok in tail[k:]:

        if tok.isdigit():

            a = int(tok)

            if a != 0:

                as_path.append(a)



    if not as_path:

        return None

    return prefix, as_path





def _run_cmd(tn: telnetlib.Telnet, cmd: str, timeout: int) -> list[str]:

    tn.write(cmd.encode("ascii", errors="ignore") + b"\n")

    text = _read_until_prompt(tn, timeout=timeout)

    return text.splitlines()





def _probe_lines(tn: telnetlib.Telnet, cmds: list[str], timeout: int) -> list[str]:

    last = []

    for cmd in cmds:

        lines = _run_cmd(tn, cmd, timeout=timeout)

        last = lines

        head = "\n".join(lines[:12])

        if "% Invalid input" in head or "% Unknown command" in head:

            continue

        # 有输出就返回（哪怕少一点）

        if lines:

            return lines

    return last





@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))

def fetch_prefix_aspaths_by_origin_asn(asn: int, ipv6: bool = False) -> tuple[list[tuple[str, list[int]]], int]:

    """

    返回 (解析结果, 原始行数)

    """

    tn = telnetlib.Telnet("route-server.he.net", 23, timeout=25)

    _login_and_setup(tn)



    if ipv6:

        cmds = [

            f"show ipv6 bgp regexp _{asn}$",

            f"show bgp ipv6 unicast regexp _{asn}$",

            f"show bgp ipv6 regexp _{asn}$",

        ]

    else:

        cmds = [

            f"show ip bgp regexp _{asn}$",

            f"show bgp ipv4 unicast regexp _{asn}$",

            f"show bgp regexp _{asn}$",

        ]



    lines = _probe_lines(tn, cmds, timeout=220)



    tn.write(b"exit\n")

    tn.close()



    out: list[tuple[str, list[int]]] = []

    for ln in lines:

        parsed = _parse_line_prefix_aspath(ln)

        if parsed:

            out.append(parsed)



    return out, len(lines)

