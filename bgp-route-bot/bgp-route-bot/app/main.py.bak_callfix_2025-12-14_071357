
import os

import re

import asyncio

from telegram import Update

from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters



from app.cache import TTLCache

from app.bgptools import fetch_asn_name_map

from app.bgptools_table import fetch_prefixes_from_bgptools_table

from app.ripe_ris import fetch_ris_aspaths_for_origin

from app.analyze import path_to_labels_full, summarize_like_sample

from app.ip_lookup import lookup_ip_to_asn



cache = TTLCache(ttl_seconds=24 * 3600)



_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

_IPV6_RE = re.compile(r"^[0-9A-Fa-f:]+$")





def _allowed(user_id: int) -> bool:

    allowed = os.getenv("ALLOWED_USERS", "").strip()

    if not allowed:

        return True

    s = set()

    for x in allowed.split(","):

        x = x.strip()

        if x.isdigit():

            s.add(int(x))

    return user_id in s





async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if not _allowed(update.effective_user.id):

        return

    await update.message.reply_text(

        "我可以直接查路由/上游路径：\n\n"

        "✅ 直接发送 IP：\n"

        "  1.1.1.1\n"

        "  2408:8a1e::1\n\n"

        "✅ 直接发送 ASN：\n"

        "  56040 或 AS56040\n\n"

        "也支持命令：/asn 56040  或  /ip 1.1.1.1\n"

        "输入 /help 查看说明"

    )





async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if not _allowed(update.effective_user.id):

        return

    await update.message.reply_text(

        "使用方法：\n\n"

        "1) 直接发送 IP：\n"

        "   1.1.1.1\n"

        "   2408:8a1e::1\n\n"

        "2) 直接发送 ASN：\n"

        "   56040 或 AS56040\n\n"

        "也支持：/asn 56040  /ip 1.1.1.1\n"

    )





async def asn_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if not _allowed(update.effective_user.id):

        return



    if not context.args:

        await update.message.reply_text("请带参数：/asn 56040  或直接发 56040")

        return



    asn_s = context.args[0].strip().upper().replace("AS", "")

    if not asn_s.isdigit():

        await update.message.reply_text("ASN 格式不对：例如 /asn 56040 或 AS56040")

        return

    asn = int(asn_s)



    ua = (os.getenv("HTTP_USER_AGENT", "") or "bgp-route-bot - contact: none").strip()



    msg = await update.message.reply_text("查询中…(1/3) 拉取 ASN 名称表")

    asn_map = cache.get("asn_map")

    if not asn_map:

        asn_map = await asyncio.to_thread(fetch_asn_name_map)

        cache.set("asn_map", asn_map)



    await msg.edit_text("查询中…(2/3) BGP.tools table 拉取 prefix 列表")

    try:

        prefixes = await asyncio.wait_for(

            asyncio.to_thread(fetch_prefixes_from_bgptools_table, asn, ua),

            timeout=180,

        )

    except asyncio.TimeoutError:

        prefixes = []



    await msg.edit_text("查询中…(3/3) RIPE RIS 拉取多观测点 AS-PATH")

    try:

        ris_paths = await asyncio.wait_for(

            asyncio.to_thread(fetch_ris_aspaths_for_origin, asn, ua),

            timeout=120,

        )

    except asyncio.TimeoutError:

        ris_paths = []



    full_labels = [path_to_labels_full(p, asn_map) for p in ris_paths]



    asn_name = asn_map.get(asn, "Unknown")

    out = []

    out.append(f"ASN号: {asn}")

    out.append(f"ASN名: {asn_name}")

    out.append("地区: Unknown\n")

    out.append("数据源统计:")

    out.append(f"- HE.net(口径对齐用 BGP.tools table): {len(prefixes)}条路由")

    out.append(f"- RIPE RIS: {len(ris_paths)} 条路径")

    out.append("- BGP.tools: (table.txt 已用) / HTML 未用")

    out.append(f"- 合并去重后: {len(prefixes)}条路由\n")

    out.append(summarize_like_sample(full_labels))



    await msg.edit_text("\n".join(out))





async def ip_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if not _allowed(update.effective_user.id):

        return



    if not context.args:

        await update.message.reply_text("用法：/ip 1.1.1.1  或直接发 IP")

        return



    ip = context.args[0].strip()

    ua = (os.getenv("HTTP_USER_AGENT", "") or "bgp-route-bot - contact: none").strip()



    msg = await update.message.reply_text("查询 IP 归属中…")

    info = await asyncio.to_thread(lookup_ip_to_asn, ip, ua)



    if not info:

        await msg.edit_text("未查询到该 IP 的 ASN 信息（可能是私网/输入错误/API 限制）")

        return



    asn = info.get("asn")

    prefix = info.get("prefix", "Unknown")

    asn_name = info.get("asn_name", "Unknown")



    await msg.edit_text(

        f"IP: {ip}\n"

        f"前缀: {prefix}\n"

        f"ASN: AS{asn}\n"

        f"ASN名: {asn_name}\n\n"

        f"正在查询 ASN 路由分析…"

    )



    context.args = [str(asn)]

    await asn_cmd(update, context)





async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE):

    if not _allowed(update.effective_user.id):

        return

    if not update.message or not update.message.text:

        return



    text = update.message.text.strip()

    if not text:

        return



    if text.startswith("/"):

        return



    t = text.upper()

    if t.startswith("AS") and t[2:].isdigit():

        context.args = [t[2:]]

        await asn_cmd(update, context)

        return

    if text.isdigit():

        context.args = [text]

        await asn_cmd(update, context)

        return



    if _IPV4_RE.match(text):

        context.args = [text]

        await ip_cmd(update, context)

        return

    if ":" in text and _IPV6_RE.match(text):

        context.args = [text]

        await ip_cmd(update, context)

        return



    await update.message.reply_text("直接发 IP（1.1.1.1）或 ASN（56040），或输入 /help")





def main():

    token = os.getenv("TG_BOT_TOKEN", "").strip()

    if not token:

        raise SystemExit("Missing TG_BOT_TOKEN in env")



    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start))

    app.add_handler(CommandHandler("help", help_cmd))

    app.add_handler(CommandHandler("asn", asn_cmd))

    app.add_handler(CommandHandler("ip", ip_cmd))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    app.run_polling(close_loop=False)





if __name__ == "__main__":

    main()

