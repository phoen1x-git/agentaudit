"""Render a round's `findings.tsv` as a single self-contained static HTML page.

    python app/make_index.py out/round-<tag> [--lang en|zh]

No backend, sortable and searchable. A static file is easy to archive and to diff
between two rounds.
"""
from __future__ import annotations

import argparse
import csv
import html
import sys
from pathlib import Path

L = {
    "en": {"sub": "{n} rows - untriaged, for human review only",
           "ph": "filter: project / file / sink / snippet...",
           "hint": "(click a header to sort; an empty verdict column means not looked at yet)"},
    "zh": {"sub": "{n} 条 · 未判定，仅供人工审阅",
           "ph": "过滤：项目 / 文件名 / sink / 片段…",
           "hint": "（点表头排序；verdict 一列留空 = 未看）"},
}

TEMPLATE = """<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8">
<title>findings - {tag}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font: 13px/1.5 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
         margin: 0; background:#f7f7f8; color:#1a1a1a; }}
  header {{ padding:12px 18px; background:#fff; border-bottom:1px solid #e3e3e6;
            position:sticky; top:0; z-index:5; }}
  h1 {{ font-size:15px; margin:0 0 8px; }}
  .mut {{ color:#8a8a90; }}
  input {{ padding:6px 10px; width:320px; border:1px solid #d0d0d6; border-radius:6px; font-size:13px; }}
  .wrap {{ padding:14px 18px; }}
  table {{ border-collapse:collapse; width:100%; background:#fff; border:1px solid #e3e3e6;
           border-radius:8px; overflow:hidden; }}
  th,td {{ padding:7px 9px; border-bottom:1px solid #eee; text-align:left; vertical-align:top; }}
  th {{ background:#fafafb; cursor:pointer; user-select:none; white-space:nowrap; position:sticky; top:64px; }}
  th:hover {{ background:#f0f0f4; }}
  tr:hover td {{ background:#fcfcfe; }}
  td.snippet {{ font-family:ui-monospace,Consolas,monospace; font-size:12px; max-width:520px; }}
  td.chain {{ font-size:11.5px; color:#666; max-width:420px; word-break:break-all; }}
  .n {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .sink {{ font-weight:600; }}
  .f {{ color:#0a58ca; }}
</style></head><body>
<header>
  <h1>findings - {tag} <span class="mut">- {sub}</span></h1>
  <div><input id="q" placeholder="{ph}" autofocus>
  <span class="mut">{hint}</span></div>
</header>
<div class="wrap">
<table id="t"><thead><tr>{head}</tr></thead><tbody>
{rows}
</tbody></table>
</div>
<script>
const tb=document.querySelector('#t tbody');
document.querySelectorAll('#t th').forEach((th,i)=>th.addEventListener('click',()=>{{
  const rows=[...tb.querySelectorAll('tr')];
  const num=i===4||i===6||i===7;
  const dir=th.dataset.d=(th.dataset.d==='1')?'-1':'1'; th.dataset.d=dir;
  rows.sort((a,b)=>{{let x=a.children[i].innerText,y=b.children[i].innerText;
    if(num){{x=parseFloat(x)||0;y=parseFloat(y)||0;return (x-y)*dir;}}
    return x.localeCompare(y)*dir;}});
  rows.forEach(r=>tb.appendChild(r));
}}));
const q=document.querySelector('#q');
q.addEventListener('input',()=>{{const v=q.value.toLowerCase();
  tb.querySelectorAll('tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(v)?'':'none');}});
</script></body></html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("round_dir", nargs="?", help="a round directory, e.g. out/round-my-round")
    ap.add_argument("--lang", default="en", choices=["en", "zh"], help="page language (default: en)")
    a = ap.parse_args()
    rd = Path(a.round_dir) if a.round_dir else None
    if not rd or not (rd / "findings.tsv").exists():
        print("usage: python app/make_index.py <round-dir> [--lang en|zh]")
        return 1
    with open(rd / "findings.tsv", encoding="utf-8-sig", newline="") as fh:
        rr = list(csv.DictReader(fh, delimiter="\t"))
    cols = list(rr[0].keys()) if rr else []
    head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
    body = []
    for r in rr:
        tds = []
        for c in cols:
            v = html.escape(r.get(c, "") or "")
            cls = ""
            if c == "snippet":
                cls = ' class="snippet"'
            elif c == "chain":
                cls = ' class="chain"'
            elif c == "sink":
                cls = ' class="sink"'
            tds.append(f"<td{cls}>{v}</td>")
        body.append("<tr>" + "".join(tds) + "</tr>")
    txt = L[a.lang]
    out = TEMPLATE.format(lang=("zh-CN" if a.lang == "zh" else "en"),
                          tag=rd.name, sub=txt["sub"].format(n=len(rr)),
                          ph=txt["ph"], hint=txt["hint"],
                          head=head, rows="\n".join(body))
    (rd / "index.html").write_text(out, encoding="utf-8")
    print(f"wrote {rd / 'index.html'} ({len(rr)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
