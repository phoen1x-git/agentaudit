"""Render a self-contained, offline HTML page for an evidence review packet."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DIMENSIONS = {
    "input_origin": "输入来源证据",
    "input_control": "输入控制能力",
    "execution_effect": "操作是否产生代码执行效果",
    "effective_guard": "防护是否有效且在执行前生效",
    "runtime_scope": "实际运行范围和权限",
    "impact": "可证实的影响",
}


def _script_json(value) -> str:
    # Escape HTML-sensitive characters so evidence text cannot terminate the data block.
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def render(packet: dict, template: dict) -> str:
    if packet.get("schema") != "agentaudit-evidence-review-pack-v1":
        raise ValueError("unsupported packet")
    if template.get("schema") != "agentaudit-human-review-submission-v1":
        raise ValueError("unsupported review template")
    if packet.get("packet_sha256") != template.get("packet_sha256"):
        raise ValueError("packet/template hash mismatch")
    if len(packet.get("cases", [])) != len(template.get("reviews", [])):
        raise ValueError("packet/template case count mismatch")

    packet_json = _script_json(packet)
    template_json = _script_json(template)
    dimensions = _script_json(DIMENSIONS)
    return f'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src data:; form-action 'none'; base-uri 'none'">
<title>代码证据复核</title>
<style>
:root {{ color-scheme: light; font-family: "Segoe UI", "Microsoft YaHei", sans-serif; color: #17202a; background: #f4f6f8; }}
body {{ margin: 0; }}
header {{ background: #18324b; color: white; padding: 1rem 1.4rem; }}
header h1 {{ margin: 0 0 .35rem; font-size: 1.25rem; }}
header p {{ margin: 0; color: #d7e4ef; }}
main {{ max-width: 1100px; margin: auto; padding: 1rem; }}
.toolbar, .card {{ background: white; border: 1px solid #d9e0e7; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
.toolbar {{ display: grid; grid-template-columns: minmax(180px, 1fr) auto auto auto; gap: .7rem; align-items: end; }}
label {{ display: block; font-weight: 600; margin: .5rem 0 .25rem; }}
input[type=text], select, textarea {{ width: 100%; box-sizing: border-box; border: 1px solid #9caab7; border-radius: 5px; padding: .55rem; font: inherit; }}
textarea {{ min-height: 7rem; resize: vertical; }}
button, .file-button {{ border: 0; border-radius: 5px; padding: .65rem .9rem; background: #1769aa; color: white; font: inherit; cursor: pointer; }}
button.secondary {{ background: #465a6d; }}
button:disabled {{ opacity: .5; cursor: not-allowed; }}
.progress {{ height: .55rem; background: #e5ebf0; border-radius: 1rem; overflow: hidden; margin: .8rem 0; }}
.progress span {{ display: block; height: 100%; background: #16815d; width: 0; }}
.case-title {{ display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; }}
.case-title h2 {{ margin: .1rem 0 .7rem; font-size: 1.2rem; }}
.muted {{ color: #516171; }}
.evidence {{ border: 1px solid #d5dfe7; border-radius: 6px; margin: .65rem 0; }}
.evidence summary {{ cursor: pointer; padding: .65rem; background: #f7f9fb; }}
.evidence pre {{ white-space: pre-wrap; overflow-wrap: anywhere; padding: .8rem; margin: 0; border-top: 1px solid #d5dfe7; background: #fbfcfd; font: 13px/1.5 Consolas, monospace; }}
.cite {{ margin-left: .7rem; white-space: nowrap; font-size: .9rem; }}
.dimensions {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: .4rem 1rem; }}
.dimension {{ border-bottom: 1px solid #edf0f2; padding-bottom: .45rem; }}
.confirm {{ display: flex; gap: .55rem; align-items: start; padding: .8rem; border: 1px solid #e0b65c; background: #fff9e8; border-radius: 6px; margin: .8rem 0; }}
.actions {{ display: flex; flex-wrap: wrap; gap: .6rem; margin-top: .8rem; }}
.error {{ color: #a12222; min-height: 1.4rem; font-weight: 600; }}
.success {{ color: #146a45; font-weight: 600; }}
.notice {{ background: #eef5fa; border-left: 4px solid #1769aa; padding: .7rem .9rem; }}
@media (max-width: 760px) {{ .toolbar {{ grid-template-columns: 1fr 1fr; }} }}
@media print {{ body {{ background: white; }} header {{ background: white; color: black; border-bottom: 1px solid #777; }} .toolbar, .review-form, .actions {{ display: none; }} main {{ max-width: none; }} }}
</style>
</head>
<body>
<header><h1>代码证据复核</h1><p>离线页面 · 不包含历史模型意见 · 由复核者独立填写</p></header>
<main>
<section class="card notice"><strong>使用说明：</strong>来源代码片段仍可能暴露项目身份。请先填写 reviewer ID，再逐案阅读证据；不确定时选“无法判断”。完成后下载复核文件，使用配套校验工具检查。</section>
<section class="toolbar">
  <div><label for="reviewer">Reviewer ID</label><input id="reviewer" type="text" autocomplete="off" placeholder="填写可区分评审者的编号"></div>
  <button id="download">下载进度 / 完成结果</button>
  <label class="file-button" for="resume">导入进度文件</label><input id="resume" type="file" accept="application/json,.json" hidden>
  <button id="clear" class="secondary">清除此页进度</button>
</section>
<div class="progress"><span id="progress-bar"></span></div>
<div id="progress-text" class="muted"></div>
<div id="case"></div>
<div id="error" class="error" role="alert"></div>
<div id="notice" aria-live="polite"></div>
</main>
<script>
"use strict";
const PACKET = {packet_json};
const TEMPLATE = {template_json};
const DIMENSIONS = {dimensions};
const STORE_KEY = "agentaudit-review-" + PACKET.packet_sha256;
const byId = id => document.getElementById(id);
let state = {{ packet_sha256: PACKET.packet_sha256, reviews: {{}}, drafts: {{}}, started: {{}}, index: 0 }};
let storageAvailable = true;
try {{ const raw = sessionStorage.getItem(STORE_KEY); if (raw) state = JSON.parse(raw); }} catch (_) {{ storageAvailable = false; }}
function persist() {{ try {{ sessionStorage.setItem(STORE_KEY, JSON.stringify(state)); }} catch (_) {{ storageAvailable = false; }} }}
function element(tag, attrs = {{}}, content = null) {{
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {{
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) throw new Error("event attributes are not accepted");
    else node.setAttribute(key, value);
  }}
  if (content !== null) node.textContent = content;
  return node;
}}
function currentCase() {{ return PACKET.cases[state.index]; }}
function getTemplateRow(reviewId) {{ return TEMPLATE.reviews.find(row => row.review_id === reviewId); }}
function ensureStart(reviewId) {{ if (!state.started[reviewId]) state.started[reviewId] = new Date().toISOString(); }}
function valueOf(form, name) {{ const node = form.elements.namedItem(name); return node ? node.value : ""; }}
function values(form, name) {{ return [...form.querySelectorAll(`[name="${{name}}"]:checked`)].map(node => node.value); }}
function showNotice(message, success = false) {{ const node = byId("notice"); node.textContent = message; node.className = success ? "success" : "muted"; }}

function render() {{
  const data = currentCase();
  const reviewId = data.review_id;
  ensureStart(reviewId);
  const host = byId("case"); host.replaceChildren();
  const title = element("div", {{class:"case-title"}});
  title.append(element("h2", {{text:`案例 ${{state.index + 1}} / ${{PACKET.cases.length}} · ${{reviewId}}`}}));
  title.append(element("span", {{class:"muted", text:`证据 ${{data.evidence.length}} 条`}}));
  const card = element("section", {{class:"card"}}); card.append(title);
  const locationLabel = data.candidate.kind === "external_analysis_result"
    ? "外部分析器候选"
    : (data.candidate.sink_name || "候选源码行");
  card.append(element("p", {{class:"muted", text:`候选位置：${{locationLabel}}，行 ${{data.candidate.line}}；引用候选源码可在下方勾选。`}}));
  card.append(element("h3", {{text:"证据片段"}}));
  for (const item of data.evidence) {{
    const details = element("details", {{class:"evidence"}});
    const summary = element("summary");
    summary.append(element("strong", {{text:`${{item.id}} · ${{item.source}}:${{item.start_line}}-${{item.end_line}}`}}));
    summary.append(element("span", {{class:"muted", text:` · ${{item.roles.join(", ")}}`}}));
    const citeLabel = element("label", {{class:"cite"}});
    const cite = element("input", {{type:"checkbox", name:"evidence_ids", value:item.id}});
    citeLabel.append(cite, document.createTextNode(" 引用此证据"));
    summary.append(citeLabel);
    details.append(summary);
    const pre = element("pre");
    pre.textContent = item.lines.map(row => `${{row.line}} | ${{row.text}}`).join("\\n");
    details.append(pre); card.append(details);
  }}
  const obs = data.tool_observations;
  card.append(element("h3", {{text:"工具观察及限制"}}));
  card.append(element("p", {{text:`状态：${{obs.status}}；范围：${{obs.scope || "未声明"}}`}}));
  for (const item of obs.observations || []) {{
    const block = element("details", {{class:"evidence"}});
    block.append(element("summary", {{text:item.kind || "观察"}}));
    block.append(element("pre", {{}}, JSON.stringify(item, null, 2)));
    card.append(block);
  }}
  if ((obs.limitations || []).length) card.append(element("p", {{class:"muted", text:"限制：" + obs.limitations.join("；")}}));
  card.append(element("h3", {{text:"仍待核对"}}));
  const unknowns = element("ul");
  for (const item of data.known_unknowns) unknowns.append(element("li", {{}}, item));
  card.append(unknowns);

  const form = element("form", {{class:"review-form"}});
  form.addEventListener("submit", event => event.preventDefault());
  const saved = state.reviews[reviewId] || state.drafts[reviewId] || getTemplateRow(reviewId) || {{}};
  const choose = (labelText, name, options, selected) => {{
    const wrapper = element("div", {{class:"dimension"}});
    wrapper.append(element("label", {{for:name, text:labelText}}));
    const select = element("select", {{name, id:name}});
    for (const [value, label] of options) {{ const option = element("option", {{value, text:label}}); if (value === selected) option.selected = true; select.append(option); }}
    wrapper.append(select); return wrapper;
  }};
  form.append(element("h3", {{text:"人工复核"}}));
  const resultWrap = element("div", {{class:"dimension"}});
  resultWrap.append(element("label", {{for:"result", text:"结论"}}));
  const result = element("select", {{id:"result", name:"result"}});
  for (const [value,label] of [["","请选择"],["confirmed","确认"],["rejected","排除"],["undetermined","无法判断"]]) {{
    const option = element("option", {{value,text:label}}); if (saved.result === value) option.selected = true; result.append(option);
  }}
  resultWrap.append(result); form.append(resultWrap);
  const dimGrid = element("div", {{class:"dimensions"}});
  for (const [key,label] of Object.entries(DIMENSIONS)) dimGrid.append(choose(label,key,[["unknown","未知"],["supported","有证据支持"],["not_supported","证据不支持"]],saved.dimensions?.[key] || "unknown"));
  form.append(dimGrid);
  const rationaleLabel = element("label", {{for:"rationale", text:"理由（至少 20 个字符）"}}); form.append(rationaleLabel);
  const rationale = element("textarea", {{id:"rationale",name:"rationale",placeholder:"说明引用了哪些证据，以及哪些问题仍未解决。"}}); rationale.value = saved.rationale || ""; form.append(rationale);
  form.append(element("label", {{for:"external", text:"外部证据或复核笔记（可留空）"}}));
  const external = element("textarea", {{id:"external",name:"external_evidence",placeholder:"记录本证据包之外使用的材料来源。"}}); external.value = (saved.external_evidence || []).join("\\n"); form.append(external);
  form.append(element("label", {{for:"questions", text:"未解决问题（可留空）"}}));
  const questions = element("textarea", {{id:"questions",name:"unresolved_questions",placeholder:"每行一项"}}); questions.value = (saved.unresolved_questions || []).join("\\n"); form.append(questions);
  const confirm = element("label", {{class:"confirm"}});
  const unseen = element("input", {{type:"checkbox",name:"history_unseen"}}); unseen.checked = saved.historical_opinion_consulted === false;
  confirm.append(unseen, document.createTextNode("我在完成本案例复核前没有查看对应的历史模型意见。")); form.append(confirm);
  const actions = element("div", {{class:"actions"}});
  const save = element("button", {{type:"button",text:"保存本案例"}});
  save.addEventListener("click", () => saveCase(form, data)); actions.append(save);
  form.append(actions); card.append(form);
  const nav = element("div", {{class:"actions"}});
  const previous = element("button", {{type:"button",class:"secondary",text:"上一个"}}); previous.disabled = state.index === 0;
  previous.addEventListener("click", () => move(-1, form));
  const next = element("button", {{type:"button",class:"secondary",text:"下一个"}}); next.disabled = state.index >= PACKET.cases.length - 1;
  next.addEventListener("click", () => move(1, form));
  nav.append(previous,next); card.append(nav); host.append(card);
  for (const item of data.evidence) if ((saved.evidence_ids || []).includes(item.id)) {{
    const box = form.querySelector(`input[name="evidence_ids"][value="${{CSS.escape(item.id)}}"]`); if (box) box.checked = true;
  }}
  byId("reviewer").value = state.reviewer_id || "";
  updateProgress();
}}

function captureDraft(form, data) {{
  const row = {{
    schema:"agentaudit-human-review-v1", review_id:data.review_id, packet_sha256:PACKET.packet_sha256,
    reviewer_id:byId("reviewer").value.trim(), review_started_at:state.started[data.review_id] || "", reviewed_at:"",
    historical_opinion_consulted:form.elements.namedItem("history_unseen").checked ? false : null,
    result:valueOf(form,"result"), rationale:valueOf(form,"rationale"), evidence_ids:values(form,"evidence_ids"),
    dimensions:Object.fromEntries(Object.keys(DIMENSIONS).map(key => [key,valueOf(form,key) || "unknown"])),
    external_evidence:valueOf(form,"external_evidence").split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean),
    unresolved_questions:valueOf(form,"unresolved_questions").split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean),
    available_evidence_ids:data.evidence.map(item=>item.id)
  }};
  return row;
}}
function saveCase(form, data) {{
  byId("error").textContent = "";
  const row = captureDraft(form,data);
  if (!row.reviewer_id) {{ byId("error").textContent="请先填写 Reviewer ID。"; return; }}
  if (row.historical_opinion_consulted !== false) {{ byId("error").textContent="请先确认没有查看本案例的历史意见。"; return; }}
  if (!["confirmed","rejected","undetermined"].includes(row.result)) {{ byId("error").textContent="请选择结论。"; return; }}
  if (row.rationale.trim().length < 20) {{ byId("error").textContent="请补充至少 20 个字符的理由。"; return; }}
  if (!row.evidence_ids.length) {{ byId("error").textContent="至少引用一条证据。"; return; }}
  row.reviewed_at = new Date().toISOString();
  state.reviewer_id = row.reviewer_id; state.reviews[data.review_id] = row; delete state.drafts[data.review_id];
  persist(); updateProgress(); showNotice("本案例已保存。请下载进度文件，作为可恢复的副本。", true);
}}
function move(delta, form) {{
  const data = currentCase();
  if (!state.reviews[data.review_id]) state.drafts[data.review_id] = captureDraft(form,data);
  state.index = Math.max(0,Math.min(PACKET.cases.length-1,state.index+delta)); persist(); byId("error").textContent=""; render();
}}
function updateProgress() {{
  const complete = Object.keys(state.reviews).length;
  byId("progress-bar").style.width = `${{100*complete/PACKET.cases.length}}%`;
  byId("progress-text").textContent = `已保存 ${{complete}} / ${{PACKET.cases.length}}；未保存的当前输入只保留在本标签页内存中。`;
}}
function exportSubmission() {{
  const reviews = TEMPLATE.reviews.map(base => state.reviews[base.review_id] || state.drafts[base.review_id] || base);
  const output = {{schema:"agentaudit-human-review-submission-v1",packet_sha256:PACKET.packet_sha256,reviews}};
  const blob = new Blob([JSON.stringify(output,null,2)+"\\n"],{{type:"application/json"}});
  const link = element("a",{{href:URL.createObjectURL(blob),download:"review-submission.json"}});
  document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(link.href),1000);
  showNotice("复核文件已下载。请妥善保管；文件包含人工判断和笔记。",true);
}}
async function importSubmission(file) {{
  byId("error").textContent="";
  try {{
    const imported = JSON.parse(await file.text());
    if (imported.packet_sha256 !== PACKET.packet_sha256 || imported.schema !== "agentaudit-human-review-submission-v1") throw new Error("文件与当前复核包不匹配。");
    const known = new Set(PACKET.cases.map(item=>item.review_id));
    const rows = imported.reviews || [];
    if (rows.some(row=>!known.has(row.review_id))) throw new Error("进度文件包含未知案例。");
    state.reviews={{}}; state.drafts={{}};
    for (const row of rows) {{
      if (row.result && row.reviewed_at) state.reviews[row.review_id]=row;
      else state.drafts[row.review_id]=row;
    }}
    state.reviewer_id = rows.find(row=>row.reviewer_id)?.reviewer_id || "";
    persist(); render(); showNotice("进度已导入。",true);
  }} catch (error) {{ byId("error").textContent=error.message || "无法读取进度文件。"; }}
}}
byId("download").addEventListener("click",exportSubmission);
byId("reviewer").addEventListener("input",event=>{{state.reviewer_id=event.target.value;persist();}});
byId("resume").addEventListener("change",event=>{{const file=event.target.files?.[0];if(file)importSubmission(file);event.target.value="";}});
byId("clear").addEventListener("click",()=>{{
  if(!confirm("清除此标签页的复核进度？请先下载需要保留的文件。")) return;
  try{{sessionStorage.removeItem(STORE_KEY);}}catch(_){{}}
  state={{packet_sha256:PACKET.packet_sha256,reviews:{{}},drafts:{{}},started:{{}},index:0}};render();showNotice("当前标签页进度已清除。",true);
}});
render();
</script>
</body>
</html>
'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        page = render(json.loads(args.packet.read_text(encoding="utf-8")),
                      json.loads(args.template.read_text(encoding="utf-8")))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(page, encoding="utf-8")
        print(f"wrote offline review page: {args.out}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"render_review_page: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
