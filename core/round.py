"""内核 · 一轮的落盘。

★ 轮次目录 = 只读快照。确认靠人改 findings.tsv 的最后一列，
   累积进 confirmations.json（本轮不做合并，先留占位）。

产出：
    out/round-YYYYMMDD/
        findings.tsv      一条一行，最后一列 verdict 留人工填
        scan.log          哪个项目跑成/没跑成、为什么（失败要出声）
        meta.json         规则版本戳 / 用时 / 目标池 / LLM 花费
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
    """Write the full Finding objects (including long fields such as the guards list).

    Note: `to_row()` stores `arg_src` as a *summary string*; the structured `arg_sources`
    list is written here too, because the re-judging paths rebuild Finding objects from
    this file. Without it they would always see an empty list, and the triage layer would
    silently lose the argument-source evidence it is supposed to reason about.
    The tsv columns are left untouched on purpose: changing them would ripple through the
    report and the HTML index.
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
