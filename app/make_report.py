"""A1 自用版入口 · 报告草稿（第④步）。

    python app/make_report.py out/round-20261009

★ 三条硬规矩（docs/95 §十⑦ / §十一 / §12.2 写的，别绕过去）：
  ① 分【已核实（读过源码）】/【未核实（未跑）】**两栏**，不许合成一句话；
  ② **不许**写"人工核实 / human-verified" —— 本流程只有「AI 复核 + 人工措辞审阅」；
  ③ 推断一律降级成疑问句（may / 可能）；**上游没查就写「未查询」**，不许假装查过。

★ 报告是**生成**的，所以"不许夸大"必须写成模板的硬约束，靠自觉一定失守。
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _kind(sink: str) -> tuple[str, str]:
    """从 sink 名字粗分类 + 给一个**方向**（不承诺有效）。"""
    s = (sink or "").lower()
    if "exec" in s or "eval" in s:
        return "代码执行", "把执行放进受限子进程/容器，或限制可用模块与内置函数"
    if "subprocess" in s or "popen" in s or "system" in s:
        return "命令执行", "避免 shell=True；对参数做白名单或严格转义"
    if any(k in s for k in ("request", "urlopen", "http", "load", "get(", "post(")):
        return "出网请求（可能 SSRF）", "目标地址走白名单；显式拒绝内网 / 链路本地 / 云元数据地址段"
    if "execute" in s or "cursor" in s:
        return "数据库执行", "参数化查询；限制可执行的语句类型"
    return "危险调用", "（待补）"


_CN_SRC = {"llm_output": "大模型的输出", "user_input": "用户输入", "tool_arg": "工具入参",
           "memory": "跨轮记忆", "config": "配置文件", "constant": "写死的常量"}


def _claims(r: dict, j: dict, kind: str) -> list[tuple[str, str, str]]:
    """把推断拆成 (标签, 结论句, 依据)。★ 结论句用疑问语气，依据单独一行给。"""
    out = []
    src = r.get("arg_source", "")
    if src in _CN_SRC:
        out.append(("实参来源", f"**可能**来自「{_CN_SRC[src]}」", j.get("arg_source_evidence", "")))
    if r.get("guards_real") == "no":
        out.append(("沿途的 if", "**可能**不构成对目标地址/实参的防护", j.get("guards_evidence", "")))
    elif r.get("guards_real") == "yes":
        out.append(("沿途的 if", "**可能**构成防护（该条据此未判 vuln）", j.get("guards_evidence", "")))
    if r.get("by_design") == "yes":
        out.append(("是不是本来的功能", "是（发这个请求/执行这段代码属本项目用途）",
                    j.get("by_design_evidence", "")))
    if r.get("scope_exceeds") == "yes":
        out.append(("是否超出预期范围", "**可能**超出（该有隔离却没有 / 可能指向任意地址）",
                    j.get("by_design_evidence", "")))
    out.append(("结论", f"因此**可能**存在{kind}风险；**可利用性未验证**", ""))
    return out


def _upstream_verdict_short(u: dict) -> str:
    if not u or u.get("error"):
        return "未查询"
    flags = []
    if u.get("archived"):
        flags.append("仓库已归档")
    if u.get("still_present") is False:
        flags.append("代码已改/已删")
    elif u.get("still_present") is None:
        flags.append("文件已不存在")
    if u.get("advisories"):
        flags.append(f"有{len(u['advisories'])}条公告")
    return "；".join(flags) if flags else "无异常"


def _upstream_block(u: dict) -> list[str]:
    if not u or u.get("error"):
        return ["- **未查询**（本轮未执行上游核实）。发信前必须补：① default_branch；"
                "② 用特征串定位该处是否还在；③ 搜该仓库/该包的公开公告。"]
    L = [f"- 仓库：`{u.get('repo')}`　default_branch：`{u.get('default_branch')}`"
         f"　最后推送：{u.get('pushed_at')}"
         + ("　★ **仓库已归档（archived）**" if u.get("archived") else "　（未归档）"),
         f"- 查询渠道：仓库元数据 / `{u.get('default_branch')}` 分支文件树 / 该文件在 HEAD 的内容 / "
         f"PyPI 包公开安全公告（GitHub Advisory），查询时间 {u.get('checked_at')}",
         f"- 用**特征串**定位："
         + ("**上游仍在**，现在第 " + str(u.get("line_now")) + " 行"
            if u.get("still_present") is True else
            ("**上游该处已找不到**（代码已改或已删）" if u.get("still_present") is False else
             "**该文件在上游已不存在**")),
         ]
    if u.get("path_now") and u.get("path_now") != u.get("path_present"):
        L.append(f"  ★ 文件位置已变：现为 `{u.get('path_now')}`")
    adv = u.get("advisories") or []
    if adv:
        L.append(f"- 该包已有 **{len(adv)} 条公开公告**（需逐条比对是否已覆盖本条，不得直接断定重复）：")
        for a in adv[:4]:
            L.append(f"    - `{a.get('ghsa')}` [{a.get('sev')}] {a.get('summary')}")
    else:
        L.append("- 该包：未查到公开公告")
    hits = u.get("issue_hits") or []
    kws = u.get("issue_keywords") or ([u["issue_keyword"]] if u.get("issue_keyword") else [])
    kw_disp = "、".join(f"`{k}`" for k in kws) if kws else "（无可辨识关键词）"
    if hits:
        L.append(f"- 仓库 issue 关键词查重（{kw_disp}）命中 {len(hits)} 条，"
                 "**需人工确认是否同一问题**：")
        for h in hits[:5]:
            L.append(f"    - #{h.get('number')} [{h.get('state')}] {h.get('title')}")
    elif kws:
        L.append(f"- 仓库 issue 关键词查重（{kw_disp}）：无命中")
    # 可报性提示（只提示，不替人决定）
    if u.get("archived"):
        L.append("- ★ **可报性提示**：仓库已归档，维护者大概率不会修 → 报出去多半是白费。")
    if u.get("still_present") is False:
        L.append("- ★ **可报性提示**：上游该处已不在 → 现在报等于报一个已经不存在的问题。")
    if adv:
        L.append("- ★ **可报性提示**：该包已有公告，**必须先比对**是否同一问题，否则是重复报。")
    L.append("- ★ 结论措辞模板：截至 " + u.get("checked_at", "?") +
             "，我们在上述渠道**未发现针对该处的既有报告**。"
             "（★ 不得写成『此漏洞从未被发现』——那超出我们实际做的动作）")
    return L


def main() -> int:
    rd = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not rd or not (rd / "findings.tsv").exists():
        print("用法: python app/make_report.py <round-dir>")
        return 1
    rows = list(csv.DictReader(open(rd / "findings.tsv", encoding="utf-8-sig"), delimiter="\t"))
    full = json.load(open(rd / "findings.json", encoding="utf-8")) if (rd / "findings.json").exists() else {}
    verd = json.load(open(rd / "verdicts.json", encoding="utf-8")) if (rd / "verdicts.json").exists() else {}
    meta = json.load(open(rd / "meta.json", encoding="utf-8")) if (rd / "meta.json").exists() else {}
    hrev = json.load(open(rd / "human_review.json", encoding="utf-8")) if (rd / "human_review.json").exists() else {}
    up = json.load(open(rd / "upstream.json", encoding="utf-8")) if (rd / "upstream.json").exists() else {}

    # ★ 候选台账状态（2026-10-13 新增）——「这条候选，我看到哪一步了」。
    #   ★ 读不到**不许阻断报告**（账本是辅助信息，不是判据）。
    ledger_st, ledger_note = {}, ""
    try:
        from core import candidate_ledger as CL
        ledger_st = CL.derive(CL.read_events())
        ledger_note = f"（台账共 {len(ledger_st)} 条候选）"
    except Exception as e:
        ledger_note = f"★ 台账读取失败，本报告不含台账列：{type(e).__name__}"

    def _ls(fp: str) -> str:
        d = ledger_st.get(fp)
        if not d:
            return "—（未入账）"
        return CL.STATUS_LABEL.get(d["status"], d["status"])

    reps = [r for r in rows if r.get("ai_verdict") == "vuln"]
    stamp = meta.get("kernel_stamp", {})
    L = [
        "# 报告草稿（自动生成）· **未经实跑验证**", "",
        "> ★ 口径声明：本报告的判定由 **AI 复核**产出，并经**人工审阅措辞**（只审『话有没有超出代码』，"
        "**不等于**确认漏洞）。文中所有推断均已降级为疑问句。**可利用性未验证。**", "",
        f"- 轮次：`{rd.name}`　生成时间：{meta.get('generated_at','?')}",
        f"- 判据版本戳：`rubric={stamp.get('rubric','?')}` `sinks={stamp.get('sinks.yml','?')}` "
        f"`filters={stamp.get('filters.yml','?')}`",
        f"- 判定花费：本轮实付 {meta.get('llm_cost_cny','?')} 元"
        f"（{meta.get('llm_calls',0)} 次调用 / {meta.get('llm_cache_hits',0)} 次命中缓存）。"
        f"★ 若要报『判定一批多少钱』，用**首次未命中**那一轮的值，别用命中缓存那轮的 0",
        f"- 候选总数 {len(rows)} → 判成 vuln **{len(reps)}** 条（其余为 not_vuln / needs_human，不在本报告）",
        "",
        "## 汇总", "",
        "> ★ 「台账」列 = 这条候选**在候选台账里的当前状态**" + ledger_note
        + "。查详情：`python core/candidate_ledger.py show <指纹>`", "",
        "| # | 项目 | 位置 | 类型 | 置信度 | 措辞审阅 | 上游 | 台账 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(reps, 1):
        kind, _ = _kind(r.get("sink", ""))
        key = f"{r['project']}:{r['file']}:{r['line']}"
        hr = hrev.get(key, {})
        hv = f"{hr.get('reviewed','')} {hr.get('result','未审')}".strip()
        u = up.get(r["fingerprint"], {})
        uv = _upstream_verdict_short(u)
        L.append(f"| {i} | {r['project']} | `{r['file']}:{r['line']}` | {kind} | "
                 f"{r.get('conf','')} | {hv} | {uv} | {_ls(r['fingerprint'])} |")
    L += ["", "## ★ 可报性结论（据上游核实，**列事实、不替人拍板**）", ""]
    for i, r in enumerate(reps, 1):
        u = up.get(r["fingerprint"], {})
        reasons = []
        if u.get("still_present") is False:
            reasons.append("上游该处已不在")
        if u.get("file_removed"):
            reasons.append("上游该文件已不存在")
        if u.get("archived"):
            reasons.append("★ 仓库已归档（维护者不会修）")
        if u.get("advisories"):
            reasons.append(f"该包已有 {len(u['advisories'])} 条公开公告")
        if u.get("issue_hits"):
            reasons.append(f"仓库 issue 命中 {len(u['issue_hits'])} 条")
        L.append(f"- **{i}. {r['project']} `{r['file']}:{r['line']}`** → "
                 + ("；".join(reasons) if reasons else "未见明显阻碍"))
    L += ["",
          "> ★ 上面每一条都只是**事实**。『报不报』是人拍的，不是工具拍的；"
          "但在按下去之前，每一条都必须先回答：**上游还在不在？有没有人已经报过？维护者会不会修？**",
          "", "---", ""]

    for i, r in enumerate(reps, 1):
        kind, fixdir = _kind(r.get("sink", ""))
        key = f"{r['project']}:{r['file']}:{r['line']}"
        hr = hrev.get(key, {})
        j = verd.get(r["fingerprint"], {})
        L += [
            f"## {i}. {r['project']} · `{r['file']}:{r['line']}` — {kind}", "",
            f"**身份指纹**：`{r['fingerprint']}`　（★ 查重/去重用它，**不要用行号**，行号会漂）  ",
            f"**AI 判定**：`{r.get('ai_verdict')}`　置信度 {r.get('conf')}　"
            f"（是不是本项目本来的功能：{r.get('by_design')}；超出预期范围：{r.get('scope_exceeds')}）  ",
            f"**措辞审阅**：{hr.get('reviewed','—')} · {hr.get('result','未审')}"
            + (f"　—— {hr.get('note')}" if hr.get("note") else ""),
            "", "### 已核实（读过源码）", "", "```python",
            f"{r['line']}: {r.get('snippet','')}", "```", "",
            f"事实：`{r.get('sink')}` 在第 {r['line']} 行被调用。以上代码为**直接摘录**，可逐字对照。",
            "",
            "### 未核实（未跑）", "",
            "以下均为**推断**，没有实跑验证，措辞按疑问处理：", "",
        ] + [
            f"- **{lbl}**：{claim}" + (f"\n  ↳ 依据：{ev}" if ev else "")
            for lbl, claim, ev in _claims(r, j, kind)
        ] + [
            "",
            "### 上游状态（由实际查询动作填充）", "",
            "> ★ 只写『我们查了哪些渠道、什么时间、结论是什么』；**不许**写成『此漏洞从未被发现』。", "",
        ] + _upstream_block(up.get(r["fingerprint"], {})) + [
            "### 可能的修法方向（未验证有效性）", "",
            f"- {fixdir}", "",
            "---", "",
        ]

    out = rd / "report_draft.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"report_draft.md 已生成：{out}（{len(reps)} 条）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
