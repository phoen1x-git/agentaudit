"""Render a human-facing report draft for the candidates triaged as `vuln`.

    python app/make_report.py out/round-<tag> [--lang en|zh]

Three rules the template enforces, because a generated report must not be able to
overstate what was actually done:

  1. Facts and inferences are kept in **separate sections** -- never merged into one sentence.
  2. The wording "verified" / "confirmed" is never used. The tool produces candidates,
     not conclusions.
  3. Every inference is phrased as a question (may / possibly). If the upstream check was
     not run, the report says so instead of implying it was.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Localised strings
# ---------------------------------------------------------------------------
S = {
    "en": {
        "title": "# Report draft (generated) - **not verified by execution**",
        "disclaimer": (
            "> The verdicts in this report were produced by **AI-assisted triage**. "
            "Every inference below is phrased as a question and **exploitability is unverified**. "
            "Treat the entries as **candidates**, not as confirmed vulnerabilities."),
        "round": "Round",
        "generated": "generated",
        "stamps": "Rule stamps",
        "cost_line": ("Triage cost this run: {cost} CNY "
                      "({calls} calls / {hits} served from cache). To quote a per-batch price, "
                      "use the first uncached run, not a cached one that reports 0."),
        "counts": "Candidates {total} -> triaged `vuln` **{n}** (the rest are not_vuln / needs_human and are not listed here)",
        "counts_all": "All **{total}** candidates are listed (no LLM triage was run, so none of them carry a verdict yet)",
        "counts_untriaged": "Candidates {total} -> **{n}** never triaged",
        "summary": "## Summary",
        "tbl_head": "| # | Rule | Project | Location | Type | Confidence | Upstream |",
        "upstream_unknown": "not checked",
        "upstream_ok": "no anomaly",
        "upstream_archived": "repo archived",
        "upstream_changed": "code changed or removed",
        "upstream_gone": "file no longer present",
        "upstream_advisories": "{n} published advisories",
        "detail": "## Findings",
        "fingerprint": "Fingerprint",
        "fingerprint_note": "for deduplication -- do **not** key on line numbers, they drift",
        "judge": "AI verdict",
        "conf": "confidence",
        "by_design": "designed feature",
        "scope": "exceeds intended scope",
        "verified_h": "### Verified (source was read)",
        "fact": "Fact: `{sink}` is called at line {line}. The excerpt above is a **verbatim** quote.",
        "unverified_h": "### Unverified (not executed)",
        "unverified_note": "Everything below is an **inference**. Nothing here was executed:",
        "arg_source": "Argument source",
        "guards": "Guards along the path",
        "design_q": "Designed feature?",
        "scope_q": "Exceeds intended scope?",
        "conclusion": "Conclusion",
        "conclusion_body": "A {kind} risk **may** exist here; **exploitability is unverified**",
        "guards_no": "**may not** effectively constrain the target value",
        "guards_yes": "**may** constitute a guard (this is why it was not triaged `vuln`)",
        "design_yes": "Yes (this call is part of what the project is for)",
        "scope_yes": "**Possibly** (no isolation where one would be expected / may point anywhere)",
        "evidence": "evidence",
        "upstream_h": "### Upstream status (filled in by an actual lookup)",
        "upstream_rule": "> Record only which channels were checked, when, and what was found. "
                         "Do **not** write \"this has never been reported\".",
        "upstream_not_run": ("- **Not checked** (the upstream lookup was not run this round). "
                             "Before disclosing, this still needs: (1) the default branch, "
                             "(2) a snippet search to see whether the site is still present, "
                             "(3) a search of public advisories for the repo/package."),
        "channels": "Channels checked: repo metadata / file tree of `{branch}` / HEAD content of the file / "
                    "public security advisories (GitHub Advisory). Checked at {when}",
        "snippet_loc": "Snippet lookup: ",
        "still_present": "**still present upstream**, now at line {line}",
        "no_longer": "**no longer found upstream** (changed or removed)",
        "file_gone": "**the file no longer exists upstream**",
        "path_moved": "  The file moved: now `{path}`",
        "advisories_h": "- This package already has **{n} public advisories** (compare each one before assuming a duplicate):",
        "no_advisories": "- This package: no public advisories found",
        "issue_hits": "- Repo issue keyword search ({kws}) returned {n} hits; **a human must confirm whether any is the same issue**:",
        "issue_none": "- Repo issue keyword search ({kws}): no hits",
        "no_kw": "(no distinctive keyword)",
        "closing_rule": ("> Every line above is a **fact**. Whether to disclose is a human decision, "
                         "not the tool's; but before acting, each entry still has to answer: "
                         "**is it still there? has anyone reported it? will the maintainers fix it?**"),
        "fix_h": "### Possible directions (effectiveness not verified)",
        "archived_warn": "The repository is archived, so maintainers are unlikely to fix anything.",
        "gone_warn": "The site is already gone upstream.",
        "adv_warn": "The package already has advisories; compare before reporting.",
        "usage": "usage: python app/make_report.py <round-dir> [--lang en|zh]",
        "done": "wrote",
        "kind_exec": "code execution",
        "kind_cmd": "command execution",
        "kind_net": "outbound request (possible SSRF)",
        "kind_db": "database execution",
        "kind_other": "dangerous call",
        "kind_unauth": "unauthenticated route",
        "kind_authincons": "authentication inconsistent within the file",
        "kind_argsrc": "argument source not determinable",
        "kind_cooc": "untrusted input and dangerous call in one expression",
        "kind_dual": "strong/weak form side by side",
        "fix_exec": "run in a restricted subprocess/container, or limit the available modules and builtins",
        "fix_cmd": "avoid shell=True; whitelist or strictly escape the arguments",
        "fix_net": "whitelist target hosts; explicitly refuse private / link-local / cloud-metadata ranges",
        "fix_db": "use parameterised queries; restrict the statement types that can run",
        "fix_other": "(to be written)",
        "fix_unauth": "require the same dependency the neighbouring routes use, or mark the route public explicitly",
        "fix_authincons": "make every route in the file declare its auth (or declare the public ones)",
        "fix_argsrc": "trace where the value comes from; if it is model output, treat it as untrusted input",
        "fix_cooc": "separate the read from the use, and validate before the dangerous call",
        "fix_dual": "use the constraining form on both paths",
        "rule_hdr": "Rule",
        "scanner_line": "Produced by: **{scanner}** (see the README for what each mode covers)",
        "no_verdict": "not triaged (no LLM run for this round)",
    },
    "zh": {
        "title": "# 报告草稿（自动生成）· **未经实跑验证**",
        "disclaimer": ("本报告的判定由 **AI 复核**产出。文中所有推断均已降级为疑问句，"
                       "**可利用性未验证**。请把它们当成**候选**，而不是已确认的漏洞。"),
        "round": "轮次",
        "generated": "生成时间",
        "stamps": "规则版本戳",
        "cost_line": ("本轮判定花费 {cost} 元（{calls} 次调用 / {hits} 次命中缓存）。"
                      "若要报『判定一批多少钱』，用**首次未命中**那一轮的值，不要用命中缓存那轮的 0。"),
        "counts": "候选总数 {total} → 判成 vuln **{n}** 条（其余为 not_vuln / needs_human，不在本报告）",
        "counts_all": "列出全部 **{total}** 条候选（本轮未跑 LLM 复核，所以都还没有判定）",
        "counts_untriaged": "候选总数 {total} → **{n}** 条从未复核",
        "summary": "## 汇总",
        "tbl_head": "| # | 规则 | 项目 | 位置 | 类型 | 置信度 | 上游 |",
        "upstream_unknown": "未查询",
        "upstream_ok": "无异常",
        "upstream_archived": "仓库已归档",
        "upstream_changed": "代码已改/已删",
        "upstream_gone": "文件已不存在",
        "upstream_advisories": "有 {n} 条公告",
        "detail": "## 明细",
        "fingerprint": "身份指纹",
        "fingerprint_note": "查重/去重用它，**不要用行号**，行号会漂",
        "judge": "AI 判定",
        "conf": "置信度",
        "by_design": "是不是本项目本来的功能",
        "scope": "是否超出预期范围",
        "verified_h": "### 已核实（读过源码）",
        "fact": "事实：`{sink}` 在第 {line} 行被调用。以上代码为**直接摘录**，可逐字对照。",
        "unverified_h": "### 未核实（未跑）",
        "unverified_note": "以下均为**推断**，没有实跑验证，措辞按疑问处理：",
        "arg_source": "实参来源",
        "guards": "沿途的 if",
        "design_q": "是不是本来的功能",
        "scope_q": "是否超出预期范围",
        "conclusion": "结论",
        "conclusion_body": "因此**可能**存在{kind}风险；**可利用性未验证**",
        "guards_no": "**可能**不构成对目标地址/实参的防护",
        "guards_yes": "**可能**构成防护（该条据此未判 vuln）",
        "design_yes": "是（该调用属本项目用途）",
        "scope_yes": "**可能**超出（该有隔离却没有 / 可能指向任意地址）",
        "evidence": "依据",
        "upstream_h": "### 上游状态（由实际查询动作填充）",
        "upstream_rule": "只写『查了哪些渠道、什么时间、结论是什么』；**不许**写成『此漏洞从未被发现』。",
        "upstream_not_run": "- **未查询**（本轮未执行上游核实）。报出去之前必须补：① default_branch；"
                            "② 用特征串定位该处是否还在；③ 搜该仓库/该包的公开公告。",
        "channels": "查询渠道：仓库元数据 / `{branch}` 分支文件树 / 该文件在 HEAD 的内容 / "
                    "公开安全公告（GitHub Advisory），查询时间 {when}",
        "snippet_loc": "用**特征串**定位：",
        "still_present": "**上游仍在**，现在第 {line} 行",
        "no_longer": "**上游该处已找不到**（代码已改或已删）",
        "file_gone": "**该文件在上游已不存在**",
        "path_moved": "  文件位置已变：现为 `{path}`",
        "advisories_h": "- 该包已有 **{n} 条公开公告**（需逐条比对是否已覆盖本条，不得直接断定重复）：",
        "no_advisories": "- 该包：未查到公开公告",
        "issue_hits": "- 仓库 issue 关键词查重（{kws}）命中 {n} 条，**需人工确认是否同一问题**：",
        "issue_none": "- 仓库 issue 关键词查重（{kws}）：无命中",
        "no_kw": "（无可辨识关键词）",
        "closing_rule": ("> 上面每一条都只是**事实**。『报不报』是人拍的，不是工具拍的；"
                         "但在按下去之前，每一条都必须先回答：**上游还在不在？有没有人已经报过？维护者会不会修？**"),
        "fix_h": "### 可能的修法方向（未验证有效性）",
        "archived_warn": "仓库已归档，维护者大概率不会修。",
        "gone_warn": "上游该处已不在（现在报等于报一个已经不存在的问题）。",
        "adv_warn": "该包已有公告，必须先比对是否同一问题，否则是重复报。",
        "usage": "用法: python app/make_report.py <round-dir> [--lang en|zh]",
        "done": "已生成",
        "kind_exec": "代码执行",
        "kind_cmd": "命令执行",
        "kind_net": "出网请求（可能 SSRF）",
        "kind_db": "数据库执行",
        "kind_other": "危险调用",
        "kind_unauth": "路由无鉴权",
        "kind_authincons": "同文件内鉴权不一致",
        "kind_argsrc": "实参来源无法判定",
        "kind_cooc": "外部输入与危险调用在同一表达式",
        "kind_dual": "强弱写法并存",
        "fix_exec": "把执行放进受限子进程/容器，或限制可用模块与内置函数",
        "fix_cmd": "避免 shell=True；对参数做白名单或严格转义",
        "fix_net": "目标地址走白名单；显式拒绝内网 / 链路本地 / 云元数据地址段",
        "fix_db": "参数化查询；限制可执行的语句类型",
        "fix_other": "（待补）",
        "fix_unauth": "挂上和相邻路由相同的鉴权依赖，或明确声明该路由为公开",
        "fix_authincons": "让文件里每个路由都显式声明自己的鉴权（公开的也要声明）",
        "fix_argsrc": "追一下这个值从哪来；如果来自模型输出，就按不可信输入处理",
        "fix_cooc": "把读取和使用拆开，在危险调用前先校验",
        "fix_dual": "两条路径都用带约束的那个写法",
        "rule_hdr": "规则",
        "scanner_line": "由 **{scanner}** 模式产出（各模式覆盖什么见 README）",
        "no_verdict": "未复核（本轮没有跑 LLM）",
    },
}

SRC_EN = {"llm_output": "LLM output", "user_input": "user input", "tool_arg": "tool argument",
          "memory": "cross-turn memory", "config": "config file", "constant": "hard-coded constant"}
SRC_ZH = {"llm_output": "大模型的输出", "user_input": "用户输入", "tool_arg": "工具入参",
          "memory": "跨轮记忆", "config": "配置文件", "constant": "写死的常量"}


# Checks whose "sink" is not a call name; classify them by rule instead.
RULE_KIND = {
    "ast/unauth-endpoint": ("kind_unauth", "fix_unauth"),
    "ast/inconsistent-auth": ("kind_authincons", "fix_authincons"),
    "ast/arg-source-unknown": ("kind_argsrc", "fix_argsrc"),
    "ast/input-to-sink": ("kind_cooc", "fix_cooc"),
    "ast/duality": ("kind_dual", "fix_dual"),
}


def _kind(sink: str, rule: str, t: dict) -> tuple[str, str]:
    mapped = RULE_KIND.get((rule or "").strip())
    if mapped:
        return t[mapped[0]], t[mapped[1]]
    s = (sink or "").lower()
    if "exec" in s or "eval" in s:
        return t["kind_exec"], t["fix_exec"]
    if "subprocess" in s or "popen" in s or "system" in s:
        return t["kind_cmd"], t["fix_cmd"]
    if any(k in s for k in ("request", "urlopen", "http", "load", "get(", "post(")):
        return t["kind_net"], t["fix_net"]
    if "execute" in s or "cursor" in s:
        return t["kind_db"], t["fix_db"]
    return t["kind_other"], t["fix_other"]


def _claims(r: dict, j: dict, kind: str, t: dict, src_map: dict) -> list[tuple[str, str, str]]:
    """Split inferences into (label, claim, evidence). Claims use questioning language."""
    out = []
    src = r.get("arg_source", "")
    if src in src_map:
        out.append((t["arg_source"], f"**may** come from \"{src_map[src]}\"", j.get("arg_source_evidence", "")))
    if r.get("guards_real") == "no":
        out.append((t["guards"], t["guards_no"], j.get("guards_evidence", "")))
    elif r.get("guards_real") == "yes":
        out.append((t["guards"], t["guards_yes"], j.get("guards_evidence", "")))
    if r.get("by_design") == "yes":
        out.append((t["design_q"], t["design_yes"], j.get("by_design_evidence", "")))
    if r.get("scope_exceeds") == "yes":
        out.append((t["scope_q"], t["scope_yes"], j.get("by_design_evidence", "")))
    out.append((t["conclusion"], t["conclusion_body"].format(kind=kind), ""))
    return out


def _upstream_verdict_short(u: dict, t: dict) -> str:
    if not u or u.get("error"):
        return t["upstream_unknown"]
    flags = []
    if u.get("archived"):
        flags.append(t["upstream_archived"])
    if u.get("still_present") is False:
        flags.append(t["upstream_changed"])
    elif u.get("still_present") is None:
        flags.append(t["upstream_gone"])
    if u.get("advisories"):
        flags.append(t["upstream_advisories"].format(n=len(u["advisories"])))
    return "; ".join(flags) if flags else t["upstream_ok"]


def _upstream_block(u: dict, t: dict) -> list[str]:
    if not u or u.get("error"):
        return [t["upstream_not_run"]]
    L = [f"- {t['channels'].format(branch=u.get('default_branch'), when=u.get('checked_at'))}"]
    if u.get("still_present") is True:
        loc = t["still_present"].format(line=u.get("line_now"))
    elif u.get("still_present") is False:
        loc = t["no_longer"]
    else:
        loc = t["file_gone"]
    L.append(f"- {t['snippet_loc']}{loc}")
    if u.get("path_now") and u.get("path_now") != u.get("path_present"):
        L.append(t["path_moved"].format(path=u.get("path_now")))
    adv = u.get("advisories") or []
    if adv:
        L.append(t["advisories_h"].format(n=len(adv)))
        for a in adv[:4]:
            L.append(f"    - `{a.get('ghsa')}` [{a.get('sev')}] {a.get('summary')}")
    else:
        L.append(t["no_advisories"])
    hits = u.get("issue_hits") or []
    kws = u.get("issue_keywords") or ([u["issue_keyword"]] if u.get("issue_keyword") else [])
    kw_disp = ", ".join(f"`{k}`" for k in kws) if kws else t["no_kw"]
    if hits:
        L.append(t["issue_hits"].format(kws=kw_disp, n=len(hits)))
        for h in hits[:5]:
            L.append(f"    - #{h.get('number')} [{h.get('state')}] {h.get('title')}")
    elif kws:
        L.append(t["issue_none"].format(kws=kw_disp))
    if u.get("archived"):
        L.append(f"- {t['archived_warn']}")
    if u.get("still_present") is False:
        L.append(f"- {t['gone_warn']}")
    if adv:
        L.append(f"- {t['adv_warn']}")
    return L


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("round_dir", nargs="?", help="a round directory, e.g. out/round-my-round")
    ap.add_argument("--lang", default="en", choices=["en", "zh"], help="report language (default: en)")
    ap.add_argument("--select", default="vuln", choices=["vuln", "all", "untriaged"],
                    help="which rows to write up: only those triaged vuln (default), every "
                         "candidate, or those that were never triaged")
    a = ap.parse_args()
    t = S[a.lang]
    src_map = SRC_EN if a.lang == "en" else SRC_ZH

    rd = Path(a.round_dir) if a.round_dir else None
    if not rd or not (rd / "findings.tsv").exists():
        print(t["usage"])
        return 1
    rows = list(csv.DictReader(open(rd / "findings.tsv", encoding="utf-8-sig"), delimiter="\t"))
    full = json.load(open(rd / "findings.json", encoding="utf-8")) if (rd / "findings.json").exists() else {}
    verd = json.load(open(rd / "verdicts.json", encoding="utf-8")) if (rd / "verdicts.json").exists() else {}
    meta = json.load(open(rd / "meta.json", encoding="utf-8")) if (rd / "meta.json").exists() else {}
    up = json.load(open(rd / "upstream.json", encoding="utf-8")) if (rd / "upstream.json").exists() else {}

    if a.select == "vuln":
        reps = [r for r in rows if (r.get("ai_verdict") or "").strip() == "vuln"]
        counts = t["counts"].format(total=len(rows), n=len(reps))
    elif a.select == "untriaged":
        reps = [r for r in rows if not (r.get("ai_verdict") or "").strip()]
        counts = t["counts_untriaged"].format(total=len(rows), n=len(reps))
    else:
        reps = list(rows)
        counts = t["counts_all"].format(total=len(rows))
    stamp = meta.get("kernel_stamp", {})
    stamp_txt = " ".join(f"`{k}={v}`" for k, v in sorted(stamp.items()) if v) or "-"
    L = [
        t["title"], "",
        t["disclaimer"], "",
        f"- {t['round']}: `{rd.name}`  |  {t['generated']}: {meta.get('generated_at', '?')}",
        f"- {t['stamps']}: {stamp_txt}",
        "- " + t["cost_line"].format(cost=meta.get("llm_cost_cny", "?"),
                                     calls=meta.get("llm_calls", 0), hits=meta.get("llm_cache_hits", 0)),
        "- " + t["scanner_line"].format(scanner=meta.get("scanner", "?")),
        "- " + counts,
        "",
        t["summary"], "",
        t["tbl_head"],
        "|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(reps, 1):
        kind, _ = _kind(r.get("sink", ""), r.get("rule", ""), t)
        u = up.get(r["fingerprint"], {})
        conf = r.get("conf") or ""
        try:
            conf_txt = f"{float(conf):.2f}" if conf not in ("", "0.0", "0") else "-"
        except ValueError:
            conf_txt = str(conf)
        L.append(f"| {i} | `{r.get('rule', '')}` | {r['project']} | `{r['file']}:{r['line']}` | {kind} | "
                 f"{conf_txt} | {_upstream_verdict_short(u, t)} |")
    L += ["", t["closing_rule"], "", "---", "", t["detail"], ""]

    for i, r in enumerate(reps, 1):
        kind, fixdir = _kind(r.get("sink", ""), r.get("rule", ""), t)
        j = verd.get(r["fingerprint"], {})
        verdict_line = (
            f"**{t['judge']}**: `{r.get('ai_verdict')}`  {t['conf']} {r.get('conf')}  "
            f"({t['by_design']}: {r.get('by_design')}; {t['scope']}: {r.get('scope_exceeds')})"
            if (r.get("ai_verdict") or "").strip() else
            f"**{t['judge']}**: {t['no_verdict']}")
        L += [
            f"## {i}. {r['project']} - `{r['file']}:{r['line']}` - {kind}", "",
            f"**{t['rule_hdr']}**: `{r.get('rule', '')}`  |  **{t['fingerprint']}**: `{r['fingerprint']}` "
            f"({t['fingerprint_note']})",
            verdict_line,
            "", t["verified_h"], "", "```python",
            f"{r['line']}: {r.get('snippet', '')}", "```", "",
            t["fact"].format(sink=r.get("sink"), line=r["line"]), "",
            t["unverified_h"], "", t["unverified_note"], "",
        ] + [
            f"- **{lbl}**: {claim}" + (f"\n  - {t['evidence']}: {ev}" if ev else "")
            for lbl, claim, ev in _claims(r, j, kind, t, src_map)
        ] + [
            "", t["upstream_h"], "", t["upstream_rule"], "",
        ] + _upstream_block(up.get(r["fingerprint"], {}), t) + [
            "", t["fix_h"], "", f"- {fixdir}", "", "---", "",
        ]

    out = rd / "report_draft.md"
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"{t['done']}: {out} ({len(reps)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
