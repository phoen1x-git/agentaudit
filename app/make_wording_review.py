"""A1 自用版入口 · 措辞审阅页（v2）。

    python app/make_wording_review.py out/round-20261009

★★ 设计原则（v1 的教训）
  v1 把 16 条全塞进来、只给一行代码、还问"整句是看到还是推断" —— 结果人答不出来。
  三条修正：
   ① ★ 只审【会报出去】的那几条（vuln）。not_vuln / needs_human 不报，审了没意义。
   ② ★ 给足够代码（sink 前后几行），不是一行。
   ③ ★ 不问"整句"，改成三道能直接答的问题，并且机器**先给一个猜**，人只需推翻或点头。
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import static_frontend as SF  # noqa: E402


def _src_root(project: str) -> str:
    """从 run_round 的目标表找到该项目的 CodeQL 库，读出源码根。"""
    from app.run_round import TARGETS  # noqa
    db = TARGETS.get(project)
    return SF._read_src_prefix(str(db)) if db else ""


def _window(root: str, rel: str, line: int, back: int = 3, fwd: int = 3) -> list[str]:
    p = Path(root) / rel if root else None
    if not p or not p.exists():
        return []
    src = p.read_text(encoding="utf-8", errors="replace").splitlines()
    lo, hi = max(1, line - back), min(len(src), line + fwd)
    return [f"{i:>5}  {src[i-1].rstrip()}" for i in range(lo, hi + 1)]


def _line_from(abs_path: str, line: int) -> str:
    try:
        src = Path(abs_path).read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= line <= len(src):
            return src[line - 1].strip()
    except OSError:
        pass
    return ""


def _guard_block(guards: list, sink_rel: str, cap: int = 8) -> list[str]:
    """★ 把"路径上压着的 if"的**真实源码**贴出来 —— 不能让人去确认一份他看不见的东西。"""
    if not guards:
        return ["（这条调用链上没有 if 守卫）"]
    out, sink_name = [], sink_rel.replace("\\", "/").split("/")[-1]
    for g in guards[:cap]:
        if "#" not in g:
            continue
        abs_p, linecol = g.rsplit("#", 1)
        head = linecol.split(":")[0]
        line = int(head) if head.isdigit() else 0
        name = abs_p.replace("\\", "/").split("/")[-1]
        tag = "" if name == sink_name else f"　（在另一个文件 {name}）"
        out.append(f"  {name}:{line}  {_line_from(abs_path=abs_p, line=line)}{tag}")
    if len(guards) > cap:
        out.append(f"  …还有 {len(guards) - cap} 处")
    return out


_CN = {"llm_output": "大模型的输出", "user_input": "用户输入", "tool_arg": "工具入参",
       "memory": "跨轮记忆", "config": "配置文件", "constant": "写死的常量",
       "yes": "是", "no": "否", "unclear": "说不准",
       "vuln": "漏洞", "not_vuln": "不是漏洞", "needs_human": "要人看"}


def _seen_vs_inferred(row: dict, j: dict) -> tuple[str, list[dict]]:
    """机器对「看到 / 推断」的**猜测**（人可推翻）。

    ★★ v3 修正：不再用"沿途那些 if 不是在防护"这种**泛泛的转述**，
      改成把判定层**自己写的证据句**原样摆出来 —— 人才能一句句对着代码核。
      （v2 的教训：审阅人指出"26 行的 if 明明有白名单"，泛泛转述经不起对。）
    """
    seen = f"第 {row.get('line')} 行就是 `{row.get('sink')}` 这个调用（下面代码里能直接看到）"
    inf: list[dict] = []

    def add(label: str, val: str, ev: str, generic: str = "") -> None:
        if val in ("", "unknown", "?", None):
            return
        inf.append({"what": f"{label}：{_CN.get(val, val)}",
                    "ev": ev or generic or "（判定层没给证据）"})

    add("实参来自", row.get("arg_source", ""), j.get("arg_source_evidence"))
    add("沿途的 if 算防护吗", row.get("guards_real", ""), j.get("guards_evidence"))
    add("是不是这个项目本来的功能", row.get("by_design", ""), j.get("by_design_evidence"))
    add("超出预期范围了吗", row.get("scope_exceeds", ""),
        j.get("scope_exceeds_evidence") or j.get("by_design_evidence"))
    return seen, inf


def main() -> int:
    rd = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not rd or not (rd / "findings.tsv").exists():
        print("用法: python app/make_wording_review.py <round-dir>")
        return 1
    rows = list(csv.DictReader(open(rd / "findings.tsv", encoding="utf-8-sig"), delimiter="\t"))
    verd = {}
    vp = rd / "verdicts.json"
    if vp.exists():
        verd = json.load(open(vp, encoding="utf-8"))
    full = {}
    fp = rd / "findings.json"
    if fp.exists():
        full = json.load(open(fp, encoding="utf-8"))

    # ★ 只审会报出去的
    must = [r for r in rows if r.get("ai_verdict") == "vuln"]
    rest = [r for r in rows if r.get("ai_verdict") != "vuln"]

    roots: dict[str, str] = {}
    L = ["# 措辞审阅 · 只审「会报出去」的几条", "",
         f"本轮 {len(rows)} 条候选，其中 **{len(must)} 条判成 vuln（会报出去）**，只有这几条需要你看。"
         f"其余 {len(rest)} 条（not_vuln / needs_human）不报，**不用审**。", "",
         "## 怎么答（三道固定问题，每条都问这三句）", "",
         "1. **这几行代码是这么写的吗？** —— 打开文件扫一眼（下面已贴出来）。",
         "2. **结论说的那个动作，在这几行里看得见吗？**",
         "3. **结论里哪一部分，是代码里没有、写的人自己推的？** —— 我先猜了一遍，你只需推翻或点头。",
         "", "★ 这是 **AI 复核**，不是人工核实。你只判「话有没有超出代码」，不判「这算不算漏洞」。", "",
         "---", ""]

    for i, r in enumerate(must, 1):
        fp = r["fingerprint"]
        j = verd.get(fp, {})
        if r["project"] not in roots:
            roots[r["project"]] = _src_root(r["project"])
        win = _window(roots[r["project"]], r["file"], int(r["line"]))
        seen, inf = _seen_vs_inferred(r, j)
        L.append(f"## {i} / {len(must)} · {r['project']} · {r['file']}:{r['line']}")
        L.append(f"判定：`vuln`　置信度 {r.get('conf')}　（AI 复核，未实跑验证）")
        L.append("")
        L.append("**【代码 · 危险调用这一处】**")
        L.append("```python")
        L += win or ["  （取不到源码）"]
        L.append("```")
        L.append("")
        L.append(f"**【调用链上压着的 if（{r.get('guards','0')} 处 · 我拿来判断「守不守得住」的）】**")
        L.append("```python")
        L += _guard_block(full.get(fp, {}).get("guards_list", []), r["file"])
        L.append("```")
        L.append("")
        L.append(f"**【我写的结论】** {r.get('ai_reason','')}")
        L.append("")
        L.append("**【我猜：哪部分代码里看得到、哪部分是推的】**")
        L.append(f"- 看得到 → {seen}")
        for x in inf:
            L.append(f"- 推出来的 → **{x['what']}**")
            L.append(f"    ↳ 我这么判的依据：{x['ev']}")
        L.append("")
        L.append("- ① 这几行是这么写的吗？　　　　　　→ 是 / 不是：____")
        L.append("- ② 那个动作在这几行里看得见吗？　　→ 看得见 / 看不见：____")
        L.append("- ③ 上面「推出来的」那几条，有没有哪条其实代码里就看得到？"
                 "　→ 没有 / 有，是第 ___ 条：____")
        L.append("")

    L += ["---", "",
          f"## 不用审的 {len(rest)} 条（不报出去）", "",
          "这些要么判了 not_vuln（不是设计功能允许的、就是实参来自配置），"
          "要么判了 needs_human（缺信息，等开关 4 补齐沙箱配置再说）。它们不进任何报告。", ""]
    from collections import Counter
    c = Counter(r.get("ai_verdict") for r in rest)
    L.append("分布：" + "，".join(f"{k} {v} 条" for k, v in c.items()))
    L.append("")
    out = rd / "wording_review.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"wording_review.md 已生成：{out}（必审 {len(must)} 条，其余 {len(rest)} 条略过）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
