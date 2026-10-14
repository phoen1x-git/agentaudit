"""路 B：给 needs_human 条目**自动往上追一层调用方**，再喂回判定层重判。

背景：
  - 假阴性抽样的 50 条里，真正悬空的是 13 条 `needs_human`；
  - 它们的 `arg_source` 几乎全是 `unknown`，卡点高度一致：
    **实参来源在调用方，不在这条 finding 所在的文件里** ——
    判定层只看到 sink 所在函数 → 只能说"依据在给定代码之外"。
  - ★ 这是**输入不够**，不是能力不够。

做法（纯补输入，不改规则）：
  1. 取该条 finding 的 `entry`（调用链起点函数名）；
  2. 在**同一仓库源码树**里找**调用这个函数的地方**（AST：Call → func 末段名 == entry）；
  3. 把**调用方函数源码**拼进 user prompt（在原有上下文之后，不改 rubric）；
  4. 重跑判定层 → 看结论有没有变、变了几条。

★★ 2026-10-13 修（第一轮实测逼出来的）：
  第一轮（35 条）跑完发现——判定层**已经拿到了调用方源码**，却仍把
  `predict(..., image_url=None, ...)`（SampleComps/ipex）判成 `vuln`：
  ★ 它**没有识别出"调用处传的是字面量 None"**。原因不是它看到了没懂，而是
  **那段信息藏在一个几十行的函数体里，要它自己去找** —— 输入给了，但**没有突出**。
  ⇒ 修法：`find_callers` 现在**同时抽出命中的 Call 节点**，把每个实参算成
  「名 = 值（性质）」列表（`_fmt_call_args`），其中 `_nature()` 会把
  「字面量 None / 字符串常量 / 变量 / 属性 / 调用结果」显式标出来，
  直接写进 prompt 的调用方块里。

★ 这是"补输入"不是"改规则"——`llm_judge.py` 的尺度一字未动。
★ 所以本工具**不改内核文件**，只在自己的 prompt 里加一段，用 `judge_one` 的
  外围方式调用（复制 `_build_user` 的输出 + 追加调用方块）。

用法：
    python tools/resolve_needs_human_callers.py --rounds round-a1b-ctxoff,round-a1b-ctxon
    python tools/resolve_needs_human_callers.py --mt 8000 --tag 20261011
    python tools/resolve_needs_human_callers.py --only boss_agent_cli,openjudge
"""
from __future__ import annotations

import argparse
import ast
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core.finding as F  # noqa: E402
from core import llm_judge as LJ  # noqa: E402
from core import srcctx as SC  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTDIR = os.path.join(ROOT, "data", "target_pool")

sys.path.insert(0, os.path.join(ROOT, "tools"))
from target_map import _SRC_MAP, _resolve_src  # noqa: E402


# ---------------------------------------------------------------------------
# ★ 实参抽取：把「调用处传了什么」直接算出来（不靠判定层自己在源码里找）
# ---------------------------------------------------------------------------
def _expr_text(node, limit: int = 80) -> str:
    """AST 节点 → 一行可读源码文本（压空白 + 截断）。"""
    try:
        s = ast.unparse(node)
    except Exception:
        s = "?"
    s = " ".join(str(s).split())
    return s if len(s) <= limit else s[:limit] + "…"


def _nature(node) -> str:
    """给实参标一个「性质」。

    ★★ 这是本次修复的核心（起因见 §工具头部「2026-10-13 修」）：
      判定层曾经**看到了调用方源码**，却仍把 `predict(image_url=None, ...)` 判成 vuln ——
      因为「实参是写死的 None」这件事要它自己去长函数体里找，它会漏。
      把性质显式写出来，「不可控的调用点」就能被一眼排除。
    """
    if isinstance(node, ast.Constant):
        v = node.value
        if v is None:
            return "   ← ★★ 字面量 None（写死的常量 ⇒ 调用点不可控）"
        if isinstance(v, str):
            return "   ← ★ 字符串字面量"
        return "   ← ★ 字面量常量"
    if isinstance(node, ast.Name):
        return "   ← 变量（★ 需再往上追它从哪来）"
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return "   ← 属性/下标表达式"
    if isinstance(node, ast.Call):
        return "   ← 函数调用结果"
    if isinstance(node, ast.JoinedStr):
        return "   ← f-string"
    return ""


def _fmt_call_args(call) -> list[str]:
    """一次调用的实参 → [「名 = 值（性质）」, ...]。"""
    out: list[str] = []
    for i, a in enumerate(getattr(call, "args", []) or []):
        out.append("位置参数#%d = %s%s" % (i + 1, _expr_text(a), _nature(a)))
    for kw in getattr(call, "keywords", []) or []:
        if kw.arg is None:                       # **kwargs 展开
            out.append("**%s%s" % (_expr_text(kw.value), _nature(kw.value)))
        else:
            out.append("%s = %s%s" % (kw.arg, _expr_text(kw.value), _nature(kw.value)))
    return out


# ---------------------------------------------------------------------------
# 调用方搜索：在仓库里找 "谁调用了 entry"
# ---------------------------------------------------------------------------
def _entry_names(entry_name: str) -> list[str]:
    """`predict.load_image` → `['load_image', 'predict']`（由内到外，最多 3 层）。

    ★★ 为什么要拆（2026-10-13 实测逼出来的）：
      sink 常出现在**嵌套函数（闭包）**里。此时 entry 形如 `outer.inner`，
      而 `inner` 只会被 `outer` 调用。若只按 `inner` 这个名字去搜，
      会搜到**别处的同名函数** —— 实测：ipex 的 `load_image` 闭包，
      被误配到 `utils.py` 里同名的模块级 `load_image`（6 个"调用方"全是噪声），
      而**真正的调用者 `outer=predict` 反而没进结果**。
      拆开后两层都搜：既给「`outer` 怎么调 `inner`」，也给「谁调 `outer`」。
    """
    parts = [p for p in re.split(r"[.\s]+", (entry_name or "").strip()) if p]
    return list(reversed(parts))[:3] or [""]


def find_callers(root: str, entry_name: str, sink_path: str,
                 limit: int = 8, max_lines: int = 60) -> list[dict]:
    """在 root 里找出**调用 entry（或其外层函数）**的函数，返回源码片段 + 实参。

    ★ 只按名字匹配（没有真类型信息）⇒ 会命中同名不同函数的噪声。排序按：
      ① **同文件命中优先**（`same_file`：闭包场景的真调用方几乎总在同文件）；
      ② 链上**由内到外**（先「谁调 inner」，再「谁调 outer」）；
      ③ 再按「与 sink 同目录」；④ 最后按路径/行号。条数受限。
    """
    names = _entry_names(entry_name)
    short = names[0]
    if not root or not short or not os.path.isdir(root):
        return []
    rel_sink = (sink_path or "").replace("\\", "/")
    sink_dir = os.path.dirname(rel_sink)
    hits: list[dict] = []
    seen_fn: set = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SC._SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            txt = SC.read_text(p)
            if not txt or not any(n and n in txt for n in names):
                continue
            try:
                tree = ast.parse(txt)
            except SyntaxError:
                continue
            rel = os.path.relpath(p, root).replace("\\", "/")
            same_file = (rel == rel_sink)
            lines = txt.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # 只跳过 **entry 本身**（最内层）；链上的外层函数（如 `outer`）
                # 恰恰是我们要的调用方，不能跳过（踩过：跳过 `predict` ⇒ 丢了
                # 「predict 怎么调 load_image」这一层，链就断了）。
                if node.name == names[0]:
                    continue
                matched = []                      # [(命中名, Call 节点)]
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        f = sub.func
                        nm = None
                        if isinstance(f, ast.Name):
                            nm = f.id
                        elif isinstance(f, ast.Attribute):
                            nm = f.attr
                        if nm and nm in names:
                            matched.append((nm, sub))
                if not matched:
                    continue
                # ★ 把命中调用的**实参**直接抽出来（本次修复点）
                calls_info = [{
                    "line": getattr(sub, "lineno", node.lineno),
                    "name": nm,
                    "text": _expr_text(sub, 140),
                    "args": _fmt_call_args(sub)[:12],
                } for nm, sub in matched[:4]]
                lo = node.lineno
                hi = getattr(node, "end_lineno", lo) or lo
                key = (p, lo)
                if key in seen_fn:
                    continue
                seen_fn.add(key)
                body = "\n".join(lines[lo - 1:hi])
                bl = body.splitlines()
                if len(bl) > max_lines:
                    body = "\n".join(bl[:max_lines]) + "\n    # ...（截断）"
                depth = min((names.index(m[0]) for m in matched), default=9)
                hits.append({
                    "file": rel, "line": lo, "qual": node.name, "body": body,
                    "same_file": same_file,
                    "near": bool(sink_dir) and os.path.dirname(rel) == sink_dir,
                    "depth": depth,
                    "calls": calls_info,
                })
    # ★ 排序：同文件 > 链上由内到外 > 同目录 > 路径/行号
    hits.sort(key=lambda h: (not h["same_file"], h["depth"],
                             not h["near"], h["file"], h["line"]))
    return hits[:limit]


# ---------------------------------------------------------------------------
# 一条 finding → 带调用方上下文的 user prompt
# ---------------------------------------------------------------------------
def build_user_with_callers(fd: F.Finding, cache: dict, callers: list[dict]) -> str:
    """复用内核的 `_build_user`（不改它），把调用方块**追加**在后面。"""
    user, _ = LJ._build_user(fd, cache)
    if not callers:
        return user
    # ★★ 2026-10-13 二修：把**整条链的实参**按「最外层 → sink」平铺在最前面。
    #    动机（实测）：一修让实参可见了，但判定层**只看了第一层调用方** ——
    #    面对 `predict.load_image`（闭包）这种嵌套，它看到「`predict` 调 `load_image` 时传的是变量
    #    `image_url`」就判 `vuln`，**没有沿链往上追**到 `llm_generate` 传的是字面量 `None`。
    #    ⇒ 不指望它自己串链，**直接把链按层排好、最外层放第一条**。
    flat = []
    for x in callers:
        for c in (x.get("calls") or []):
            # ★ 别写 `x.get("depth") or 9` —— depth=0 会被 `or` 当成假值变成 9 ！
            #   （踩过：导致"最外层"标签全错、链的顺序整个倒过来。零成本打印才发现。）
            dv = x.get("depth")
            flat.append((9 if dv is None else int(dv), x, c))
    flat.sort(key=lambda t: -t[0])                 # depth 大 = 更外层 ⇒ 排前面
    chain_block = ""
    if flat:
        dmax = max(t[0] for t in flat)
        lines = ["\n\n【★ 实参传递链（已按「最外层 → 紧邻 sink」排好 —— **请从第一条读起**）】"]
        for d, x, c in flat[:8]:
            where = ("最外层" if d == dmax else ("中间层" if d else "紧邻 sink"))
            lines.append("  [%s] `%s` 调用 `%s`：`%s`"
                         % (where, x["qual"], c.get("name") or "?", c["text"]))
            for a in c["args"]:
                if "←" in a:                       # 只留有性质标注的（信息量最大）
                    lines.append("        · %s" % a)
        lines.append("  ★★ 判「可控性」请以**最外层**那条为准：若最外层传的是字面量常量/None，"
                     "则这条链在本仓库内**不可控**，请据此判定，不要因为中间层是变量就判可控。")
        chain_block = "\n".join(lines) + "\n"

    # ★★ 2026-10-13 三修：**去噪**。
    #    实测（`--tag callerfix_v2`）：312/327 即使把最外层的 `image_url=None` 摆在第一条，
    #    判定层仍判 `vuln` —— 因为它同时还看到 4 个「按名匹配」的**同名噪声**
    #    （`utils.py` 里另有同名 `load_image`，传的是变量 `img_path` / `f.name`），被带偏。
    #    ⇒ 规则：**只要有同文件命中，就只用同文件的**（闭包场景的真调用方几乎总在同文件）；
    #      没有同文件命中时才退回按名匹配 —— 对普通模块级函数保持原有行为。
    same = [x for x in callers if x.get("same_file")]
    dropped: list[dict] = []
    if same:
        dropped = [x for x in callers if not x.get("same_file")]
        use = same
    else:
        use = callers
    chunks = []
    for x in use:
        tag = "（★ 与 sink 同文件）" if x.get("same_file") else (
            "（★ 与 sink 同目录）" if x.get("near") else "（★ 仓库内按名匹配，可能是同名噪声）")
        seg = (f"── `{x['file']}:{x['line']}` 的函数 `{x['qual']}`{tag}\n")
        # ★★ 本次修复：把「它怎么调用入口函数、传了什么实参」**显式列出**
        for c in (x.get("calls") or []):
            seg += (f"   ★ 它这样调用 `{c.get('name') or (fd.entry or '?')}`"
                    f"（`{x['file']}:{c['line']}`）：`{c['text']}`\n")
            for a in c["args"]:
                seg += f"       · {a}\n"
        seg += f"```python\n{x['body']}\n```"
        chunks.append(seg)
    noise_note = ""
    if dropped:
        noise_note = ("  ★ 已略去 %d 个「按名匹配」的候选 —— 它们与 sink **不在同一文件**，\n"
                      "    大概率是别处的**同名函数**（本仓库同名函数很常见），只按名字匹配不可靠，\n"
                      "    故**不作为可控性依据**。\n" % len(dropped))
    block = ("\n\n【调用方源码（★ 本次补充：调用链起点 **"
             + (fd.entry or "?") + "** 是在哪里被调用的）】\n"
             "  下面是本仓库里**调用入口函数（或其外层函数）的那些函数**。\n"
             "  ★ 每个调用方下面已**直接抽出它调用时传的实参**（含性质标注）——**优先看那一行**：\n"
             "    「字面量 None / 字符串常量」= 调用点不可控；\n"
             "    「HTTP 请求体 / 用户命令 / LLM 产出 / 上游变量」= 可控（但要看它自己从哪来）。\n"
             + noise_note
             + "\n".join(chunks) + "\n")
    return user + chain_block + block


def _mk_finding(rec: dict) -> "F.Finding":
    fd = F.Finding(project=rec.get("project", ""))
    fd.fingerprint = rec.get("fingerprint", "")
    fd.rule = rec.get("rule", "")
    fd.sink_func = rec.get("sink", "")
    fd.sink_uri = rec.get("file", "")
    fd.sink_line = int(rec.get("line") or 0)
    fd.depth = int(rec.get("depth") or 0)
    fd.variants = int(rec.get("variants") or 1)
    fd.entry = rec.get("entry", "")
    fd.entries = rec.get("entries", "")
    fd.snippet = rec.get("snippet", "")
    fd.chain = rec.get("chain", "")
    fd.guards = list(rec.get("guards_list") or [])
    fd.arg_sources = rec.get("arg_sources") or []
    proj = (rec.get("project") or "").lower()
    root = _SRC_MAP.get(proj, "")
    if not root:
        from target_map import _SRC_MAP as M2  # noqa
        import re as _re
        base = _re.split(r"[-_]\d", proj)[0]
        root = M2.get(base, "")
    fd.src_root = root
    return fd


def collect(rounds: list[str], only: list[str],
            rows: set | None = None, verdicts: set | None = None) -> list[tuple[str, dict]]:
    out = []
    seen = set()
    for tag in rounds:
        f = os.path.join(ROOT, "out", tag, "findings.json")
        if not os.path.exists(f):
            continue
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for fp, r in d.items():
            # ★ 2026-10-13 加：verdicts 可调 —— 默认只收 needs_human（原行为不变），
            #   但验证"修完之后 vuln 会不会被纠正"时必须能收 vuln 条目。
            if verdicts and (r.get("ai_verdict") or "").strip() not in verdicts:
                continue
            if fp in seen:
                continue
            if only and (r.get("project") or "").lower() not in only:
                continue
            # ★ 2026-10-13 加：`--rows` 小批回归（格式 `project:文件名:行号`）
            if rows:
                key = "%s:%s:%s" % ((r.get("project") or "").lower(),
                                    os.path.basename(r.get("file") or ""),
                                    r.get("line"))
                if key not in rows:
                    continue
            seen.add(fp)
            r = dict(r)
            r["_round"] = tag
            out.append((tag, r))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", default="", help="逗号分隔；默认扫全部轮")
    ap.add_argument("--only", default="", help="限定 project 短名，逗号分隔")
    ap.add_argument("--mt", default="8000")
    ap.add_argument("--tag", default="20261011")
    # ★★ 2026-10-13 加：按 sink 关键词过滤。
    #    动机：单轮 `needs_human` 可有 200+ 条（全跑 ≈6.7 元），而"优先族"
    #    （requests/httpx/urllib/client，≈35 条 ≈1.1 元）才是值得先验证的。
    #    ★ 没这个参数就只能全跑，等于放弃"先小批验证再决定"的省钱纪律。
    ap.add_argument("--sinks", default="",
                    help='按 sink 关键词过滤（小写子串，逗号分隔）。例：--sinks "requests,httpx,urllib,client"')
    # ★ 2026-10-13 加：`--rows` 小批回归（改完工具必须先拿已知样本验，再跑全量）。
    ap.add_argument("--rows", default="",
                    help='限定具体条目，逗号分隔，格式 `project:文件名:行号`'
                         '（例：samplecomps:ipex_inference.py:312）。用于小批回归。')
    ap.add_argument("--verdicts", default="needs_human",
                    help='收哪些判定结论（逗号分隔；默认 needs_human；'
                         '`all` = 不过滤。验证"vuln 是否被纠正"时用）。')
    # ★ 2026-10-13 加：跑全量时**跳过已跑过的族**（否则等于重复花钱）。
    ap.add_argument("--skip-sinks", default="",
                    help='按 sink 关键词**排除**（小写子串，逗号分隔）。'
                         '例：--skip-sinks "requests,httpx,urllib,client"')
    a = ap.parse_args()

    rounds = (a.rounds.split(",") if a.rounds
              else sorted(os.path.basename(os.path.dirname(f))
                          for f in glob.glob(os.path.join(ROOT, "out", "round-*", "findings.json"))))
    only = [x.strip().lower() for x in a.only.split(",") if x.strip()]
    rows = {x.strip().lower() for x in a.rows.split(",") if x.strip()} or None
    vs = {x.strip().lower() for x in a.verdicts.split(",") if x.strip()}
    if "all" in vs or not vs:
        vs = None
    items = collect(rounds, only, rows, vs)
    if a.sinks:
        keys = [x.strip().lower() for x in a.sinks.split(",") if x.strip()]
        before = len(items)
        items = [(t, r) for (t, r) in items
                 if any(k in (str(r.get("sink") or "")).lower() for k in keys)]
        print(f"★ --sinks 过滤：{before} → {len(items)} 条（关键词 {keys}）")
    if a.skip_sinks:
        keys = [x.strip().lower() for x in a.skip_sinks.split(",") if x.strip()]
        before = len(items)
        items = [(t, r) for (t, r) in items
                 if not any(k in (str(r.get("sink") or "")).lower() for k in keys)]
        print(f"★ --skip-sinks 排除：{before} → {len(items)} 条（排除关键词 {keys}）")
    print(f"needs_human 条目 {len(items)} 条（轮次 {len(rounds)} 个）")
    if not items:
        return 0
    print(f"★ 预估花费 ≈ {len(items) * 0.03:.1f} 元（{len(items)} 条 × ~0.03 元）")

    os.environ["AF_JUDGE_MT"] = str(a.mt)
    results = []
    for tag, rec in items:
        fd = _mk_finding(rec)
        # 调用方源码
        sp = _resolve_src(rec) or ""
        callers = find_callers(fd.src_root, fd.entry, sp)
        cache: dict = {}
        user = build_user_with_callers(fd, cache, callers)
        try:
            r = LJ.LC.ask_json(LJ.rubric_text(), user, tag=f"callers-{a.tag}",
                               max_tokens=int(a.mt))
            r.pop("_raw", None)
            LJ._apply(fd, r)
            verdict, conf, reason = fd.ai_verdict, fd.ai_confidence, fd.ai_reason
            note = "OK"
        except Exception as e:
            verdict, conf, reason = "error", 0.0, f"{type(e).__name__}: {e}"[:200]
            note = "FAILED"

        results.append({
            "fingerprint": rec.get("fingerprint"),
            "project": rec.get("project"),
            "file": rec.get("file"),
            "line": rec.get("line"),
            "sink": rec.get("sink"),
            "entry": rec.get("entry"),
            "orig_round": tag,
            "orig_verdict": rec.get("ai_verdict"),
            "orig_arg_source": rec.get("arg_source"),
            "n_callers": len(callers),
            "callers": [{"file": c["file"], "line": c["line"], "qual": c["qual"]}
                        for c in callers],
            "new_verdict": verdict,
            "new_conf": conf,
            "new_arg_source": fd.arg_source,
            "new_by_design": fd.by_design,
            "new_scope_exceeds": fd.scope_exceeds,
            "new_guards_real": fd.guards_real,
            "new_reason": reason,
            "note": note,
        })
        arrow = "→" if verdict != "needs_human" else "="
        print(f"  {rec.get('project'):<18} {os.path.basename(rec.get('file',''))}:{rec.get('line'):<5} "
              f"callers={len(callers):<2} {arrow} {verdict:11} conf={conf:.2f} "
              f"asrc={fd.arg_source:<10} [{note}]")
        if verdict != "needs_human" and verdict != "error":
            print(f"      理由: {reason[:130]}")

    os.makedirs(OUTDIR, exist_ok=True)
    out = os.path.join(OUTDIR, f"needs_human_callers_{a.tag}.json")
    json.dump({"_meta": {"mt": a.mt, "n": len(items), "rounds": rounds},
               "results": results},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    from collections import Counter
    c = Counter(r["new_verdict"] for r in results)
    print(f"\n重判后分布: {dict(c)}")
    resolved = [r for r in results if r["new_verdict"] in ("vuln", "not_vuln")]
    print(f"★ 自动解决（脱离 needs_human）：{len(resolved)}/{len(items)}")
    for r in resolved:
        print(f"    {r['project']:<18} {os.path.basename(r['file'])}:{r['line']} "
              f"→ {r['new_verdict']}  {r['new_reason'][:80]}")
    print(f"\nJSON: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
