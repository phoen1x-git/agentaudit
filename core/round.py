"""内核 · 一轮的落盘。

★ 轮次目录 = 只读快照。确认靠人改 findings.tsv 的最后一列，
   累积进 confirmations.json（本轮不做合并，先留占位）。

产出：
    out/round-YYYYMMDD/
        findings.tsv      一条一行，最后一列 verdict 留人工填
        scan.log          哪个项目跑成/没跑成、为什么（失败要出声）
        meta.json         判据版本戳 / 用时 / 目标池 / LLM 花费
"""
from __future__ import annotations

import csv
import json
import time
from datetime import datetime
from pathlib import Path

from . import finding as F


def new_round_dir(base: Path, tag: str | None = None) -> Path:
    tag = tag or datetime.now().strftime("%Y%m%d")
    d = base / f"round-{tag}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_findings(path: Path, findings: list[F.Finding]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=F.COLS, delimiter="\t")
        w.writeheader()
        for fd in findings:
            w.writerow(fd.to_row())


def write_findings_json(path: Path, findings: list[F.Finding]) -> None:
    """完整 Finding（含 guards 列表这种长字段），给审阅页/报告用。

    ★★★ 修过一个**核心管线 bug**：以前这里只写 `to_row()`，
      而 `to_row()` 里的 `arg_src` 是**摘要字符串**（`arg0:param(x@f.py:81)`），
      **结构化列表 `arg_sources` 根本没落盘**。
      而所有"从 json 重建 Finding"的路径（`tools/rejudge_rows.py`、`tools/judge_round.py`、
      `tools/ab_judge_rubric.py`）读的都是 **`arg_sources`** → ★ **永远是空列表**。

      ★★ 后果（实测：一轮 5363 行结果里，`arg_sources` 有值的 **0 条**）：
        1. `AF_JUDGE_ARGCTX`（**默认开**、文档说它治「依据在给定代码之外」这个第一大瓶颈）
           **在所有复判路径上完全空转** —— 机制本身是好的（实测开/关能差 1000+ 字符的 user），
           缺的是**输入**；
        2. ★★ **原始判定与复判的输入不对等**：原始轮次里 `arg_sources` 在内存里是有的，
           复判时丢了 → **三道检查 SOP 第①关（复判 3 次）用的是一把证据更少的尺子**。
           昨晚"复判时结论退回 needs_human"、"路B 产物必须带调用方上下文才复现"
           —— 其中一部分很可能就是**这个丢字段**造成的，而不是"配置不同"。

      ★ 修法选**只加 json、不动 tsv**：`to_row()` 与 `COLS` 一字不改
        （tsv 的列变了会波及报告/审阅页），只在 json 里补上结构化字段。
      ⚠️ **历史轮次的 `findings.json` 补不回来**（那些文件里本来就没写过）→
        受影响的对照必须**在新轮次上重做**（写明过）。
    """
    d = {}
    for fd in findings:
        row = fd.to_row()
        row["guards_list"] = list(fd.guards)
        row["arg_sources"] = list(fd.arg_sources)      # ★★ 关键补字段
        # ★★ 并入补证层后追加：不写这几个键，investigation 的结果就存不下来
        #    （实测：`rebuilt.investigation == {}`，27 个键全丢）。只加 json 的键，tsv 不动。
        row["language"] = fd.language
        row["analysis_provenance"] = fd.analysis_provenance
        row["investigation"] = fd.investigation
        row["verification"] = fd.verification
        row["backend_evidence"] = fd.backend_evidence
        row["entry_profile"] = fd.entry_profile        # ★ 入口形态（第五步接进判定层的那份数据）
        row["src_root"] = fd.src_root                  # 读的人要能对着源码看
        # ★★ tsv 会把 snippet/chain 截断（表格宽度有限），
        #    json 若只存 to_row() 那几列，往返一次就**永久丢掉缩进和完整调用链**
        #    （实测：'    return exec(value)' 读回来变成 'return exec(value)'）。
        #    这几个 `*_full` 键就是给 read_findings_json 还原用的。
        row["snippet_full"] = fd.snippet
        row["chain_full"] = fd.chain
        row["sink_col"] = fd.sink_col
        row["ai_confidence"] = fd.ai_confidence
        d[fd.fingerprint] = row
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=1)


def write_verdicts(path: Path, findings: list[F.Finding]) -> None:
    """把判定层原始 JSON 落盘（保全证据，报告要引用）。"""
    d = {fd.fingerprint: fd.judge_json for fd in findings if fd.judge_json}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(d, fh, ensure_ascii=False, indent=1)


def write_meta(path: Path, meta: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)


# ------------------------------------------------ ★ 逐靶增量落盘
# 为什么要有它
# ------------
# `run_round` 原本是**跑完所有靶才写一次** findings/verdicts。
# 实测代价：一轮 46 个目标跑到 42 个被中断 ⇒ **6500 秒的活全丢**，
# 只剩 scan.log 里的逐靶计数，候选明细一条不剩。
# ⇒ 长轮次（几十个靶）必须**每个靶跑完就落一次盘**，并且**重启时能读回来接着跑**。
#
# ★ 只落"这个靶的候选"，不碰最终产物：最终 findings.tsv/json 仍由原路径写，
#   所以**下游（报告 / 审阅页 / 记录）看到的格式一字未变**。
# ★ 用 `asdict` 存**全部字段**（含 `guards` 列表与 `arg_sources`），读回时 `Finding(**d)` 即可 ——
#   避免重演那个"只写 to_row() ⇒ arg_sources 永远是空"的坑。
def partial_dir(rd: Path) -> Path:
    d = rd / "partial"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _partial_path(d: Path, name: str) -> Path:
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in name)
    return d / f"{safe}.json"


def write_partial(d: Path, name: str, findings: list[F.Finding]) -> None:
    """把**单个靶**的候选原子落盘（先写 .tmp 再 replace，防写一半被杀）。"""
    import os
    from dataclasses import asdict
    p = _partial_path(d, name)
    tmp = p.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in findings], fh, ensure_ascii=False)
    os.replace(tmp, p)


def load_partial(d: Path, name: str) -> list[F.Finding] | None:
    """读回某靶上次的结果。**没有文件 → None**（别把"空结果"和"没跑过"混了）。"""
    p = _partial_path(d, name)
    if not p.exists():
        return None
    try:
        rows = json.load(open(p, encoding="utf-8"))
    except Exception:
        return None                      # 文件坏了就当没跑过，重跑一遍（不静默吞）
    out: list[F.Finding] = []
    for r in rows:
        try:
            out.append(F.Finding(**r))
        except TypeError:                # 字段对不上（旧版本存的）→ 整靶重跑
            return None
    return out


class ScanLog:
    """一行一条，失败必须出声。"""

    def __init__(self, path: Path):
        self.path = path
        self._fh = open(path, "w", encoding="utf-8")
        self.t0 = time.time()

    def log(self, msg: str) -> None:
        line = f"[{time.time() - self.t0:7.1f}s] {msg}"
        print(line)
        self._fh.write(line + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def read_findings_json(path: Path) -> list[F.Finding]:
    """Rebuild a round without replacing structured evidence with the TSV summary.

    Supports older rounds; absent evidence is left absent rather than inferred.
    The separate verdicts file carries raw responses, provenance and policy adjustments.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    sidecar = path.with_name("verdicts.json")
    verdicts = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.exists() else {}
    out = []
    for fp, row in data.items():
        fd = F.Finding(project=row["project"], language=row.get("language", "python"), fingerprint=fp, rule=row.get("rule", ""),
                       sink_func=row.get("sink", ""), sink_uri=row.get("file", ""),
                       sink_line=int(row.get("line") or 0), sink_col=int(row.get("sink_col") or 0),
                       entry=row.get("entry", ""), depth=int(row.get("depth") or 0),
                       guards=row.get("guards_list", []),
                       snippet=row.get("snippet_full", row.get("snippet", "")),
                       chain=row.get("chain_full", row.get("chain", "")),
                       variants=int(row.get("variants") or 1), entries=row.get("entries", ""),
                       src_root=row.get("src_root", ""), arg_sources=row.get("arg_sources", []),
                       analysis_provenance=row.get("analysis_provenance", {}),
                       investigation=row.get("investigation", {}),
                       verification=row.get("verification", {}),
                       backend_evidence=row.get("backend_evidence", {}),
                       entry_profile=row.get("entry_profile", {}),
                       ai_confidence=float(row.get("ai_confidence", row.get("conf")) or 0),
                       judge_json=verdicts.get(fp, {}))
        for name in ("ai_verdict", "by_design", "scope_exceeds", "arg_source", "guards_real",
                     "ai_reason", "verdict"):
            setattr(fd, name, row.get(name, ""))
        out.append(fd)
    return out
