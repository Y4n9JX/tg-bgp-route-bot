
from collections import Counter



# CM 特化（只在 ASN=56040 时启用）

ACCESS_WHITELIST = {"CMI", "China Unicom", "China Telecom", "CMIN2"}

UPSTREAM_WHITELIST = {"Telia", "Lumen", "Cogent", "HE", "TATA Communications"}



# RIS 路径非常多时，为了速度做抽样统计（不影响大趋势）

MAX_SAMPLES = 60000





def normalize_asn_label(asn: int, name: str | None) -> str:

    n = (name or "").strip()

    nu = n.upper()



    # 常见硬编码映射（可扩展）

    if asn == 56040:

        return "CM"

    if asn == 58453:

        return "CMI"

    if asn == 1299:

        return "Telia"

    if asn == 3356:

        return "Lumen"

    if asn == 174:

        return "Cogent"

    if asn == 6939:

        return "HE"

    if asn == 6453:

        return "TATA Communications"



    if "CHINA MOBILE" in nu or "CMNET" in nu:

        return "CM"

    if "CHINA UNICOM" in nu or "UNICOM" in nu:

        return "China Unicom"

    if "CHINA TELECOM" in nu:

        return "China Telecom"

    if "CMIN2" in nu:

        return "CMIN2"



    if "TELIA" in nu:

        return "Telia"

    if "LUMEN" in nu or "LEVEL 3" in nu or "CENTURYLINK" in nu:

        return "Lumen"

    if "COGENT" in nu:

        return "Cogent"

    if "HURRICANE" in nu or "HE.NET" in nu:

        return "HE"

    if "TATA" in nu:

        return "TATA Communications"



    return n[:60] if n else f"AS{asn}"





def _clean_as_path(as_path: list[int]) -> list[int]:

    out = []

    prev = None

    for a in as_path:

        if a == 0:

            continue

        if prev == a:

            continue

        out.append(a)

        prev = a

    return out





def path_to_labels_full(as_path: list[int], asn_name: dict[int, str]) -> list[str]:

    p = _clean_as_path(as_path)

    return [normalize_asn_label(a, asn_name.get(a)) for a in p]





def _dedup_labels(labels: list[str]) -> list[str]:

    out = []

    for x in labels:

        if not out or out[-1] != x:

            out.append(x)

    return out





def _sample_iter(items: list, max_samples: int = MAX_SAMPLES):

    n = len(items)

    if n <= max_samples:

        for x in items:

            yield x

        return

    step = max(1, n // max_samples)

    for i in range(0, n, step):

        yield items[i]





def summarize_generic(paths_full_labels: list[list[str]]) -> str:

    """

    通用版：任何 ASN 都会输出

    - T1: 最后一跳（origin）

    - T2: 倒数第二 -> 最后

    - T3: 倒数第三 -> 倒数第二 -> 最后

    """

    total_all = len(paths_full_labels)

    if total_all == 0:

        return "路由分析:\n(无数据)"



    c1 = Counter()

    c2 = Counter()

    c3 = Counter()



    sampled = list(_sample_iter(paths_full_labels))

    total = len(sampled)



    for labels in sampled:

        labels = _dedup_labels(labels)

        if not labels:

            continue



        o = labels[-1]

        c1[(o,)] += 1



        if len(labels) >= 2:

            c2[(labels[-2], o)] += 1



        if len(labels) >= 3:

            c3[(labels[-3], labels[-2], o)] += 1



    lines = ["路由分析:"]

    if total != total_all:

        lines.append(f"(统计抽样：{total}/{total_all} 条路径)")



    for (o,), v in c1.most_common(10):

        lines.append(f"{v * 100.0 / total:.1f}% [T1] {o}")



    for (a, o), v in c2.most_common(20):

        lines.append(f"{v * 100.0 / total:.1f}% [T2] {a} -> {o} -> END")



    for (u, a, o), v in c3.most_common(20):

        lines.append(f"{v * 100.0 / total:.1f}% [T3] {u} -> {a} -> {o} -> END")



    return "\n".join(lines)





def summarize_cm(paths_full_labels: list[list[str]]) -> str:

    """

    CM 特化：只统计以 CM 结尾，并且过滤出你关心的接入/上游组合

    """

    total_all = len(paths_full_labels)

    if total_all == 0:

        return "路由分析:\n(无数据)"



    c2 = Counter()

    c3 = Counter()



    sampled = list(_sample_iter(paths_full_labels))

    total = len(sampled)



    for labels in sampled:

        labels = _dedup_labels(labels)

        if not labels or labels[-1] != "CM":

            continue



        if len(labels) >= 2 and labels[-2] in ACCESS_WHITELIST:

            c2[(labels[-2], "CM")] += 1



        if len(labels) >= 3:

            up, acc = labels[-3], labels[-2]

            if acc in ACCESS_WHITELIST and up in UPSTREAM_WHITELIST:

                c3[(up, acc, "CM")] += 1



    lines = ["路由分析:"]

    if total != total_all:

        lines.append(f"(统计抽样：{total}/{total_all} 条路径)")



    lines.append(f"{100.0:.1f}% [T1] CM")



    for (a, o), v in c2.most_common(20):

        lines.append(f"{v * 100.0 / total:.1f}% [T2] {a} -> {o} -> END")



    for (u, a, o), v in c3.most_common(20):

        lines.append(f"{v * 100.0 / total:.1f}% [T3] {u} -> {a} -> {o} -> END")



    return "\n".join(lines)





def summarize_for_asn(paths_full_labels: list[list[str]], target_asn: int) -> str:

    return summarize_cm(paths_full_labels) if target_asn == 56040 else summarize_generic(paths_full_labels)

