"""候选台账 —— 「这一条候选，我看到哪一步了」。

★★ 与 `core/ledger.py` 的区别（别混）：
  · `core/ledger.py`  = **目标台账**：哪些**靶**挖过、用哪种形态挖的 → `target_ledger.json`
  · 本模块（candidate）= **候选台账**：每一条**候选**的状态（看过没/报没报/排除了没）→ `candidate_ledger.jsonl`

★ 为什么需要：
  项目定位是「**用户只做两件事：确认真假 + 决定报不报**」。
  但每轮产出上百条候选、报告是一轮一份独立的 → **"哪些看过、哪些已报、哪些已排除"没有累积记录**
  → 每次都得重看 → 那个定位根本不成立。

★ 设计（三个刻意的选择）：
  1. **只追加**（append-only JSONL）：不做"更新"，只记"发生了什么"。
     状态是**算出来的**（`derive()`），不是存出来的 —— 这样**永远不会出现两份状态打架**。
  2. **主键用引擎已有的 `fingerprint`**（`core/finding.py:make_fingerprint`）
     = `相对路径:sha1(project|路径|sink名|归一化后的代码行)[:10]`。
     ★ **它不含行号** —— 所以**代码上下移动几行，指纹不变**（行号会漂，指纹不会）。
     行号仍然单独存一份，只为**展示**用。
  3. **事件类型少而明确**：`seen` / `review` / `reported` / `excluded` / `fixed`。
     ★ `review` = 「有人看过它」的记录，带 `who` 字段（`ai` / `user`）——
     **不许把 AI 的判断写成"人工核实"**（项目红线），所以这个字段必须区分。

用法：
    python core/candidate_ledger.py add-round round-argattr_gt12   # 把一轮的候选记进来（幂等）
    python core/candidate_ledger.py list --status todo             # ★ 待你处理的
    python core/candidate_ledger.py list --status reported
    python core/candidate_ledger.py show sampleagent/actions/action_node.py:ccd4382db3
    python core/candidate_ledger.py mark <fp> --event excluded --reason "不可达：唯一调用方传常量" --dim "③谁能碰到"
    python core/candidate_ledger.py mark --fp <fp> --event reported --ref "上游单号" --date 2026-10-08
    python core/candidate_ledger.py mark --fp <fp> --event review --who ai --note "本地实跑通过（函数级）"
    python core/candidate_ledger.py stats
    python core/candidate_ledger.py render                        # 生成人读版 candidate_ledger.md
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "data" / "target_pool" / "candidate_ledger.jsonl"
VIEW = ROOT / "data" / "target_pool" / "candidate_ledger.md"

# ★ 只开这五类（见模块头注释第 3 条）
EVENTS = ("seen", "review", "reported", "excluded", "fixed")

# 终态优先级：一个候选可能同时有多个终态事件（比如先 excluded 后又 reported），
#   ★ 顺序 = "越靠后越最终"。`reported` 永远压过 `excluded`。
TERMINAL_ORDER = ("excluded", "fixed", "review", "reported")


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 读写
# ---------------------------------------------------------------------------
def read_events() -> list[dict]:
    if not LEDGER.exists():
        return []
    out = []
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # ★ 坏行不静默丢：留个记号，便于发现"谁把文件写坏了"
            out.append({"event": "_badline", "raw": line[:200]})
    return out


def append_events(evts: list[dict]) -> int:
    """只追加。★ 调用方负责幂等。"""
    if not evts:
        return 0
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a", encoding="utf-8", newline="\n") as f:
        for e in evts:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return len(evts)


# ---------------------------------------------------------------------------
# 状态推导（★ 状态是算出来的，不是存出来的）
# ---------------------------------------------------------------------------
def derive(events: list[dict]) -> dict[str, dict]:
    """把事件流折成「每个指纹的当前状态」。

    返回 {fp: {...}}，每项含：
      status       : pending / reported / excluded / fixed / human_only
      llm_verdict  : 最近一次 seen 里的 ai_verdict（没有则 ""）
      rounds       : 出现在哪些轮次（去重、保序）
      last_seen    : 最后一次 seen 的时间
      meta         : 最近一次 seen 的展示字段（project/file/line/sink/arg_source…）
      trail        : 非 seen 的事件（人工/已报/排除/已修）—— 这就是"我做到哪一步了"
    """
    st: dict[str, dict] = {}
    for e in events:
        if e.get("event") == "_badline":
            continue
        fp = e.get("fp")
        if not fp:
            continue
        d = st.setdefault(fp, {
            "fp": fp, "status": "pending", "llm_verdict": "", "rounds": [],
            "last_seen": "", "meta": {}, "trail": [],
        })
        ev = e.get("event")
        if ev == "seen":
            r = e.get("round")
            if r and r not in d["rounds"]:
                d["rounds"].append(r)
            d["last_seen"] = e.get("ts") or d["last_seen"]
            d["llm_verdict"] = e.get("verdict") or d["llm_verdict"]
            d["meta"] = {k: e.get(k) for k in
                         ("project", "file", "line", "sink", "entry",
                          "conf", "by_design", "arg_source")}
        else:
            d["trail"].append(e)

    for fp, d in st.items():
        kinds = {t.get("event") for t in d["trail"]}
        status = "pending"
        for k in TERMINAL_ORDER:                 # 越靠后越最终
            if k in kinds:
                # ★ 事件名 `review` → 状态名 `reviewed`（两个词性：动作 vs 状态）
                status = {"review": "reviewed"}.get(k, k)
        d["status"] = status
    return st


STATUS_LABEL = {
    "pending": "待处理",
    "reported": "已报",
    "excluded": "已排除",
    "fixed": "上游已修",
    "reviewed": "已审阅（未报未排除）",
}


# ---------------------------------------------------------------------------
# add-round：从一轮的 findings.json 记 seen（★ 幂等）
# ---------------------------------------------------------------------------
def cmd_add_round(tag: str, force: bool = False, only_fps: set | None = None) -> int:
    """把某轮的 `seen` 事件记进台账。

    ★ `only_fps`（2026-10-13 加）：**只补指定指纹**。
      用途 = 只为某几条候选补「来源轮次 + 位置 + LLM 判定」这些元数据，
      **不把整轮的候选都灌进来**（否则"待处理"会被冲爆，账本反而失去意义）。
      典型场景：某条候选已经报出去了，但它的轮次没入过账 ⇒ 只补它自己。
    """
    fj = ROOT / "out" / tag / "findings.json"
    if not fj.exists():
        print(f"[FATAL] 找不到 {fj}")
        return 2
    data = json.load(open(fj, encoding="utf-8"))
    existing = read_events()
    done = {(e.get("fp"), e.get("round")) for e in existing if e.get("event") == "seen"}
    ts = _now()
    evts, skipped, missed = [], 0, []
    for fp, r in data.items():
        if only_fps is not None and fp not in only_fps:
            continue
        if (fp, tag) in done:
            skipped += 1
            continue
        evts.append({
            "ts": ts, "event": "seen", "fp": fp, "round": tag,
            "project": r.get("project"), "file": r.get("file"), "line": r.get("line"),
            "sink": r.get("sink"), "entry": r.get("entry"),
            "verdict": r.get("ai_verdict"), "conf": r.get("conf"),
            "by_design": r.get("by_design"), "arg_source": r.get("arg_source"),
        })
    if only_fps is not None:
        found = {e["fp"] for e in evts}
        missed = [fp for fp in only_fps if fp not in found]
        for fp in missed:
            print(f"  ★ 指纹在该轮里没找到：{fp}")
    n = append_events(evts)
    print(f"[add-round] {tag}：本轮 {len(data)} 条候选 → 新记 {n} 条"
          f"{f'，已存在跳过 {skipped} 条（幂等）' if skipped else ''}")
    print(f"            台账 → {LEDGER}（共 {len(existing) + n} 个事件）")
    return 0


# ---------------------------------------------------------------------------
# list / show / stats
# ---------------------------------------------------------------------------
def _fmt_row(fp: str, d: dict) -> str:
    m = d.get("meta") or {}
    verdict = (d.get("llm_verdict") or "-")[:12]
    return "%-58s %-12s %-16s %s:%s" % (
        fp if len(fp) <= 58 else "…" + fp[-57:], verdict,
        (m.get("project") or "")[:16], (m.get("file") or "").split("/")[-1], m.get("line"))


def cmd_list(status: str, project: str = "", verdict: str = "", limit: int = 0) -> int:
    st = derive(read_events())
    rows = []
    for fp, d in st.items():
        if status != "all":
            if status == "todo":
                # ★ 待处理 = 没有终态事件，且 LLM 认为值得看
                if d["trail"]:
                    continue
                if d["llm_verdict"] not in ("vuln", "needs_human"):
                    continue
            elif d["status"] != status:
                continue
        if project and (d["meta"].get("project") or "") != project:
            continue
        if verdict and d["llm_verdict"] != verdict:
            continue
        rows.append((fp, d))
    rows.sort(key=lambda x: (x[1]["meta"].get("project") or "", x[1]["meta"].get("file") or "",
                             x[1]["meta"].get("line") or 0))
    print(f"★ status={status}"
          f"{f' project={project}' if project else ''}"
          f"{f' verdict={verdict}' if verdict else ''}  →  {len(rows)} 条")
    print("-" * 104)
    if not rows:
        print("（空）")
        return 0
    by_proj: dict[str, list] = {}
    for fp, d in rows:
        by_proj.setdefault((d["meta"].get("project") or "?"), []).append((fp, d))
    shown = 0
    for proj in sorted(by_proj):
        print(f"\n[{proj}]  {len(by_proj[proj])} 条")
        for fp, d in by_proj[proj]:
            print("   " + _fmt_row(fp, d))
            shown += 1
            if limit and shown >= limit:
                print("   …（--limit 截断）")
                return 0
    return 0


def _resolve_fp(needle: str) -> list[str]:
    st = derive(read_events())
    if needle in st:
        return [needle]
    return [fp for fp in st if needle in fp]


def cmd_show(needle: str) -> int:
    fps = _resolve_fp(needle)
    if not fps:
        print(f"（没有匹配 {needle} 的候选）")
        return 1
    if len(fps) > 1:
        print(f"★ 匹配到 {len(fps)} 条，请写更完整：")
        for fp in fps[:20]:
            print("   " + fp)
        return 1
    fp = fps[0]
    st = derive(read_events())[fp]
    print(f"★ {fp}")
    print(f"  状态      : {st['status']}（{STATUS_LABEL[st['status']]}）")
    print(f"  LLM 判定  : {st['llm_verdict']}   置信度 {st['meta'].get('conf')}"
          f"   by_design={st['meta'].get('by_design')}   arg_source={st['meta'].get('arg_source')}")
    print(f"  出现轮次  : {', '.join(st['rounds'])}")
    print(f"  最近一次  : {st['last_seen']}")
    print(f"  位置      : {st['meta'].get('project')} / {st['meta'].get('file')}:{st['meta'].get('line')}"
          f"   sink={st['meta'].get('sink')}   entry={st['meta'].get('entry')}")
    print()
    if st["trail"]:
        print("★ 我不算 LLM 判定、只记人为动作 —— 这就是「做到哪一步了」：")
        for e in st["trail"]:
            extra = {k: v for k, v in e.items() if k not in ("ts", "event", "fp")}
            print(f"  {e.get('ts')}  {e.get('event'):9s}  {json.dumps(extra, ensure_ascii=False)}")
    else:
        print("（还没有任何人为动作 —— 属待处理）")
    return 0


def cmd_stats() -> int:
    ev = read_events()
    st = derive(ev)
    print(f"★ 候选台账  {LEDGER}")
    print(f"  事件总数 {len(ev)} ｜ 候选总数 {len(st)} ｜ 文件 {'存在' if LEDGER.exists() else '尚未创建'}")
    print()
    cnt: dict[str, int] = {}
    for d in st.values():
        cnt[d["status"]] = cnt.get(d["status"], 0) + 1
    for k in ("pending", "reported", "excluded", "fixed", "reviewed"):
        if k in cnt:
            print("  %-24s %5d" % (STATUS_LABEL[k], cnt[k]))
    print()
    # ★ 待处理按 LLM 判定分
    todo = [d for d in st.values() if not d["trail"] and d["llm_verdict"] in ("vuln", "needs_human")]
    c2: dict[str, int] = {}
    for d in todo:
        c2[d["llm_verdict"]] = c2.get(d["llm_verdict"], 0) + 1
    print("★ 待你处理的 %d 条：" % len(todo))
    for k, v in sorted(c2.items(), key=lambda x: -x[1]):
        print(f"    LLM 判 {k:12s} {v:5d}")
    return 0


# ---------------------------------------------------------------------------
# mark：记人为动作
# ---------------------------------------------------------------------------
def cmd_mark(needle: str, event: str, reason: str = "", dim: str = "",
             ref: str = "", channel: str = "", date: str = "", note: str = "",
             who: str = "", force_fp: str = "") -> int:
    """记一条人为动作。

    ★ `force_fp` 用于**回填历史**：那些候选来自还没录入台账的轮次。
      台账**不要求先有 `seen`** —— 因为状态是算出来的，事件谁先谁后都行。
    """
    if event not in EVENTS or event == "seen":
        print(f"[FATAL] mark 只接受 {[e for e in EVENTS if e != 'seen']}")
        return 2
    if force_fp:
        fp = force_fp
    else:
        fps = _resolve_fp(needle)
        if len(fps) != 1:
            print(f"[FATAL] 匹配到 {len(fps)} 条（要恰好 1 条）：")
            for x in fps[:20]:
                print("   " + x)
            return 2
        fp = fps[0]
    e = {"ts": _now(), "event": event, "fp": fp}
    if event == "review":
        # ★ 默认 ai —— 不许把 AI 的判断写成"人工核实"
        e["who"] = who or "ai"
    if reason:
        e["reason"] = reason
    if dim:
        e["dim"] = dim            # ★ 四维里的哪一维（①缺陷 ②设防 ③谁能碰到 ④上游）
    if ref:
        e["ref"] = ref
    if channel:
        e["channel"] = channel
    if date:
        e["date"] = date
    if note:
        e["note"] = note
    append_events([e])
    print(f"✅ {fp}\n   → {json.dumps(e, ensure_ascii=False)}")
    return 0


# ---------------------------------------------------------------------------
# render：人读版
# ---------------------------------------------------------------------------
def cmd_render() -> int:
    st = derive(read_events())
    order = ("reported", "pending", "excluded", "fixed", "human_only")
    L = ["# 候选台账（自动生成，勿手改）", "",
         f"> 生成时间：{_now()} ｜ 事件源：`data/target_pool/candidate_ledger.jsonl`"
         f" ｜ 候选 {len(st)} 条", "",
         "★ 状态是**算出来的**（只追加事件，不存状态）⇒ 不会出现两份状态打架。",
         "★ 待处理 = **没有人为动作** 且 LLM 判定 ∈ {vuln, needs_human}。",
         "",
         "| 状态 | 条数 |", "|---|---|"]
    cnt: dict[str, int] = {}
    for d in st.values():
        cnt[d["status"]] = cnt.get(d["status"], 0) + 1
    for k in order:
        if k in cnt:
            L.append(f"| {STATUS_LABEL[k]} | {cnt[k]} |")
    L.append("")

    def _block(status: str, title: str, filt=None):
        rows = [(fp, d) for fp, d in st.items() if d["status"] == status and (filt is None or filt(d))]
        rows.sort(key=lambda x: (x[1]["meta"].get("project") or "", x[1]["meta"].get("line") or 0))
        L.append(f"## {title}（{len(rows)} 条）")
        L.append("")
        if not rows:
            L.append("（空）")
            L.append("")
            return
        by_proj: dict[str, list] = {}
        for fp, d in rows:
            by_proj.setdefault(d["meta"].get("project") or "?", []).append((fp, d))
        for proj in sorted(by_proj):
            L.append(f"### {proj}（{len(by_proj[proj])} 条）")
            L.append("")
            L.append("| 文件:行 | sink | LLM 判定 | 轮次 | 备注 |")
            L.append("|---|---|---|---|---|")
            for fp, d in by_proj[proj]:
                m = d["meta"]
                note = ""
                for t in d["trail"][-1:]:
                    note = t.get("reason") or t.get("ref") or t.get("note") or ""
                L.append("| `%s:%s` | %s | %s | %s | %s |" % (
                    m.get("file"), m.get("line"), m.get("sink") or "",
                    d["llm_verdict"] or "-", ",".join(d["rounds"][-2:]), note[:60]))
            L.append("")

    _block("reported", "★ 已报（终态）")
    _block("pending", "★★ 待你处理",
           filt=lambda d: not d["trail"] and d["llm_verdict"] in ("vuln", "needs_human"))
    _block("excluded", "已排除（终态）")
    _block("fixed", "上游已修（终态）")
    _block("reviewed", "已审阅（未报未排除）")
    VIEW.write_text("\n".join(L), encoding="utf-8")
    print(f"✅ 人读版 → {VIEW}（{len(L)} 行）")
    return 0


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="候选台账（每条候选做到哪一步）")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("add-round", help="把一轮的 findings.json 记进台账（幂等）")
    p.add_argument("tag")
    p.add_argument("--fp", dest="fps", default="",
                   help="★ 只补这些指纹（逗号分隔）—— 用于给单条候选补来源元数据，不灌整轮")

    p = sub.add_parser("list", help="列候选")
    p.add_argument("--status", default="todo",
                   choices=["todo", "pending", "reported", "excluded", "fixed", "human_only", "all"])
    p.add_argument("--project", default="")
    p.add_argument("--verdict", default="")
    p.add_argument("--limit", type=int, default=0)

    p = sub.add_parser("show", help="看一条的完整历史")
    p.add_argument("needle")

    p = sub.add_parser("mark", help="记人为动作")
    p.add_argument("needle")
    p.add_argument("--event", required=True,
                   choices=[e for e in EVENTS if e != "seen"])
    p.add_argument("--reason", default="")
    p.add_argument("--dim", default="", help="四维里的哪一维：①缺陷 ②设防 ③谁能碰到 ④上游")
    p.add_argument("--ref", default="", help="上游单号，如 上游单号")
    p.add_argument("--channel", default="", help="github-issue / email / …")
    p.add_argument("--date", default="")
    p.add_argument("--note", default="")
    p.add_argument("--who", default="", choices=["", "ai", "user"],
                   help="review 事件专用：谁看过（★ 默认 ai；不许把 AI 判断写成人工）")
    p.add_argument("--fp", default="", dest="force_fp",
                   help="★ 回填历史：直接给指纹（该候选可能不在已录入的轮次里）")

    sub.add_parser("stats", help="总览")
    sub.add_parser("render", help="生成人读版 md")

    a = ap.parse_args()
    if a.cmd == "add-round":
        only = {x.strip() for x in (getattr(a, "fps", "") or "").split(",") if x.strip()} or None
        return cmd_add_round(a.tag, only_fps=only)
    if a.cmd == "list":
        return cmd_list(a.status, a.project, a.verdict, a.limit)
    if a.cmd == "show":
        return cmd_show(a.needle)
    if a.cmd == "mark":
        return cmd_mark(a.needle, a.event, a.reason, a.dim, a.ref, a.channel, a.date,
                        a.note, a.who, a.force_fp)
    if a.cmd == "stats":
        return cmd_stats()
    if a.cmd == "render":
        return cmd_render()
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
