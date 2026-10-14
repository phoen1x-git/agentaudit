"""内核 · 一轮的落盘。

★ 轮次目录 = 只读快照（docs/95 §九 9.1）。确认靠人改 findings.tsv 的最后一列，
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

    ★★★ 2026-10-12 修一个**核心管线 bug**：以前这里只写 `to_row()`，
      而 `to_row()` 里的 `arg_src` 是**摘要字符串**（`arg0:param(x@f.py:81)`），
      **结构化列表 `arg_sources` 根本没落盘**。
      而所有"从 json 重建 Finding"的路径（`tools/rejudge_rows.py`、`tools/judge_round.py`、
      `tools/ab_judge_rubric.py`）读的都是 **`arg_sources`** → ★ **永远是空列表**。

      ★★ 后果（实测 2026-10-12：全仓 5363 行，`arg_sources` 有值的 **0 条**）：
        1. `AF_JUDGE_ARGCTX`（**默认开**、文档说它治「依据在给定代码之外」这个第一大瓶颈）
           **在所有复判路径上完全空转** —— 机制本身是好的（实测开/关能差 1000+ 字符的 user），
           缺的是**输入**；
        2. ★★ **原始判定与复判的输入不对等**：原始轮次里 `arg_sources` 在内存里是有的，
           复判时丢了 → **三关 SOP 第①关（复判 3 次）用的是一把证据更少的尺子**。
           昨晚"复判时结论退回 needs_human"、"路B 产物必须带调用方上下文才复现"
           —— 其中一部分很可能就是**这个丢字段**造成的，而不是"配置不同"。

      ★ 修法选**只加 json、不动 tsv**：`to_row()` 与 `COLS` 一字不改
        （tsv 的列变了会波及报告/审阅页），只在 json 里补上结构化字段。
      ⚠️ **历史轮次的 `findings.json` 补不回来**（那些文件里本来就没写过）→
        受影响的对照必须**在新轮次上重做**（在 `docs/189` 里写明了）。
    """
    d = {}
    for fd in findings:
        row = fd.to_row()
        row["guards_list"] = list(fd.guards)
        row["arg_sources"] = list(fd.arg_sources)      # ★★ 关键补字段
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
