# -*- coding: utf-8 -*-
"""★ 把 TaintP2X 的 LLM source 定义（llms_sources.pysa，Apache-2.0）搬成我们的 sources.yml 格式。

为什么要有这个脚本（而不是手抄）：
  · 手抄 94 条必错，且无法自检覆盖率；
  · 本脚本内置一张**人工决策表**（哪些名算「独特」可裸加，哪些算「通用」必须带对象约束），
    并**自动校验 94 条 def 全部有归属** —— 少一条就报错退出。

★★ 决策原则（沿用 docs/203 §二 的区分）：
  · 「独特方法名」= 现实中几乎不可能是别的东西的方法 → 可裸加（kind: method，不带 obj_suffix）。
  · 「通用方法名」= create / run / query / call / execute 这类到处都有的名字 →
    ★ 必须带 obj_suffix 约束，否则会把 ORM 的 Model.objects.create()、cursor.execute()
    之类当成「不可信输入」，刻度会当场失控（这正是 docs/203 §二 表里担心的误伤）。
  · obj_suffix 取自 TaintP2X 定义里「倒数第二段」（即调用接收对象）——
    这是对「全限定名」的**忠实翻译**，不是我们额外加的启发式。

★ 为什么不用全限定名精确匹配：我们的静态前端不做 import 解析，
  只能拿到 `obj.toString()`（源码里写的那个接收者文本）。
  → 这是**已知的近似**，会写在产物的 note 里，不藏着。
"""
import os
import re
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PYSA = os.path.join(ROOT, "data", "vendor_taintp2x", "llms_sources.pysa")
OUT_YML = os.path.join(ROOT, "core", "config", "sources_tp2x.yml")

# ---------- 我们现有 sources.yml 里已有的 method 名（不重复输出，只用于覆盖率核对）----------
ALREADY = {
    "chat", "invoke", "generate", "completion", "complete", "predict", "ask",
}

# ---------- 人工决策表 ----------
# 类 1：独特方法名 → 可裸加
UNIQUE = [
    "stream_chat", "achat", "chat_stream",
    "generate_content", "generate_content_async",
    "generate_text", "generate_text_async", "generate_message",
    "create_async", "createChatCompletion", "createChatCompletionAsync", "async_run",
    "initiate_chat", "solve_task", "publish_message",
    "invoke_prompt", "invoke_function",
    "acreate", "_generate",
]

# 类 2：通用方法名 → 必须带接收者约束（取 TaintP2X 定义的「倒数第二段」）
#
# ★★ 语义是**精确名**（QL 侧生成 `getObject().(Attribute).getName() in [...]`），
#   **不是**子串/后缀 —— 第一版按子串写，漏了 anthropic 的 `messages`；
#   后来发现 `toString()` 对链式属性只给 "Attribute"，才改成 getName() 精确匹配。
# ★★ 自检会核对「每个 def 的倒数第二段是否在这个名单里」，漏一条就 FATAL。
GENERIC = {
    "create": [
        "completions", "ChatCompletion", "Completion",
        "AsyncChatCompletion", "messages", "async_completions",
    ],
    "run": [
        "Pipeline", "Agent", "HuggingFaceTGIGenerator", "OllamaGenerator",
        "OpenAIGenerator", "BabyAGI", "Environment", "DialogueAgent", "replicate",
    ],
    "query":   ["as_chat_engine"],
    "call":    ["Generation", "AsyncGeneration"],
    "execute": ["Task"],
}

# ---------- 启发式告警：短名 / 通用词被归为「独特」时提示复核 ----------
COMMON_WORDS = {
    "call", "run", "get", "set", "add", "new", "make", "send", "read", "load",
    "save", "open", "close", "write", "exec", "eval", "apply", "start", "stop",
    "create", "update", "delete", "query", "fetch", "find", "search", "list",
}


def parse_defs(path):
    """从 .pysa 里取出所有 `def a.b.c(` 的 dotted 名（顺序保留）。"""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^def\s+([A-Za-z_][\w.]*)\s*\(", line)
            if m:
                out.append(m.group(1))
    return out


def main():
    if not os.path.exists(PYSA):
        print("[FATAL] 找不到 TaintP2X 定义：%s" % PYSA)
        return 2
    defs = parse_defs(PYSA)
    print("[in] %d 条 def" % len(defs))

    # 每条 def 的末段 / 倒数第二段
    rows = []
    for d in defs:
        segs = d.split(".")
        rows.append({"full": d, "last": segs[-1], "prev": segs[-2] if len(segs) >= 2 else ""})

    # ---------- 覆盖率自检 ----------
    last_names = sorted({r["last"] for r in rows})
    handled = set(ALREADY) | set(UNIQUE) | set(GENERIC)
    missing = [n for n in last_names if n not in handled]
    if missing:
        print("[FATAL] 以下末段方法名**没有归属**，请补进 UNIQUE / GENERIC：")
        for n in missing:
            print("   %s  (出现 %d 次)" % (n, sum(1 for r in rows if r["last"] == n)))
        return 3

    # ---------- 覆盖率自检 2：通用名的「倒数第二段」必须**精确**落在接收者名单里 ----------
    # ★ 为什么必须查这一层：QL 生成的是 `...getObject().(Attribute).getName() in [...]`，
    #   即**精确名**。若某个 def 的接收者段不在名单里，那条定义就是**白搬的**
    #   ——而外层自检（只看末段名）发现不了。第一版就漏了 anthropic 的 messages。
    uncovered = []
    for name, objs in GENERIC.items():
        for r in rows:
            if r["last"] != name:
                continue
            if r["prev"] not in objs:
                uncovered.append((r["full"], r["prev"], objs))
    if uncovered:
        print("[FATAL] 以下 def 的接收者段**不在 obj_names 里**（白搬）：")
        for full, prev, objs in uncovered:
            print("   %-60s prev=%-18s obj_names=%s" % (full, prev, objs))
        return 4

    # ---------- 启发式告警 ----------
    warn = []
    for n in UNIQUE:
        if n in COMMON_WORDS or len(n) <= 4:
            warn.append(n)
    if warn:
        print("[WARN] 以下名字被归为「独特」，但看起来像通用词，请复核：%s" % ", ".join(warn))

    # 每个 op 归属到哪一类，并记下它来自哪些 def（note）
    def src_of(last, prev=None):
        return [r["full"] for r in rows
                if r["last"] == last and (prev is None or r["prev"] == prev)]

    entries = []

    e = {
        "id": "llm-sdk-unique",
        "kind": "method",
        "names": sorted(UNIQUE),
        "note": "TaintP2X 的 %d 个独特方法名（裸加，无需对象约束）" % len(UNIQUE),
        "provenance": sorted(UNIQUE),
    }
    entries.append(e)

    for name in sorted(GENERIC):
        objs = GENERIC[name]
        fulls = src_of(name)
        e = {
            "id": "llm-sdk-%s" % name,
            "kind": "method",
            "obj_names": objs,
            "names": [name],
            "note": "通用名 %s，仅在接收者末段属性名 ∈ %s 时才算源（TaintP2X 的 %d 条）"
                    % (name, "/".join(objs), len(fulls)),
            "provenance": fulls,
        }
        entries.append(e)

    # ---------- 统计交集：TaintP2X 里已有我们认识的名 ----------
    covered = [n for n in last_names if n in ALREADY]
    print("[covered-by-existing] %s" % ", ".join(covered))
    print("[unique] %d 个名 → 覆盖 %d 条 def"
          % (len(UNIQUE), sum(1 for r in rows if r["last"] in UNIQUE)))
    print("[generic+obj] %d 个名 → 覆盖 %d 条 def"
          % (len(GENERIC), sum(1 for r in rows if r["last"] in GENERIC)))
    print("[already] %d 个名 → 覆盖 %d 条 def"
          % (len(covered), sum(1 for r in rows if r["last"] in ALREADY)))

    # ---------- 写 yml（手工拼，不用 yaml.dump，保持注释与可读性）----------
    L = []
    L.append("# ★ 由 tools/import_tp2x_sources.py 从 data/vendor_taintp2x/llms_sources.pysa 生成，不要手改。")
    L.append("#")
    L.append("# 来源：TaintP2X（ICSE 2026）LLM source 定义，Apache-2.0。原文件 %d 条 def。" % len(defs))
    L.append("# 用法：AF_SOURCES_FILE=core/config/sources_tp2x.yml（不设 = 基线 A 组，行为完全不变）")
    L.append("#")
    L.append("# ★ 结构说明见脚本头部：独特名裸加；通用名必须带 obj_names（接收者末段属性名，精确匹配）。")
    L.append("# ★ 已知近似：TaintP2X 是「全限定名 / 类型级」定义，我们只能做「语法级」——")
    L.append("#   QL 侧用 Attribute.getName() 取接收者链的**末段属性名**：")
    L.append("#   client.chat.completions.create(...) → 末段属性名 completions → 命中。")
    L.append("")
    L.append("version: 1")
    L.append("updated: 2026-10-12")
    L.append("")
    L.append("sources:")
    for e in entries:
        L.append("  - id: %s" % e["id"])
        L.append("    kind: %s" % e["kind"])
        if "obj_names" in e:
            L.append('    obj_names: [%s]' % ", ".join(e["obj_names"]))
        L.append("    names: [%s]" % ", ".join(e["names"]))
        L.append("")
    txt = "\n".join(L) + "\n"
    os.makedirs(os.path.dirname(OUT_YML), exist_ok=True)
    with open(OUT_YML, "w", encoding="utf-8", newline="\n") as f:
        f.write(txt)
    print("[out] %s（%d 个条目）" % (OUT_YML, len(entries)))

    # 同时落一份 JSON 供实验脚本读（含 provenance，便于事后归因）——
    # ★ 这份才是「哪些 def 贡献了哪些条目」的完整账本。
    side = os.path.join(ROOT, "data", "target_pool", "tp2x_sources_map.json")
    with open(side, "w", encoding="utf-8") as f:
        json.dump({
            "n_defs": len(defs),
            "defs": defs,
            "already": sorted(ALREADY),
            "unique": UNIQUE,
            "generic": GENERIC,
            "entries": entries,
            "last_name_freq": {n: sum(1 for r in rows if r["last"] == n) for n in last_names},
        }, f, ensure_ascii=False, indent=2)
    print("[out] %s" % side)
    return 0


if __name__ == "__main__":
    sys.exit(main())
