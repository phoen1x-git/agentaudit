"""Kernel: writing a round to disk.

A round directory is a read-only snapshot. Confirmation is done by a human editing the last
column of `findings.tsv`; the results accumulate in `confirmations.json`.

Layout:
    out/round-<tag>/
        findings.tsv     one row per candidate; the last column is for a human to fill in
        findings.json    the same rows plus the long fields (guards, argument sources)
        scan.log         which project ran, which did not, and why (failures are loud)
        meta.json        version stamps / duration / costs
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
        row["arg_sources"] = list(fd.arg_sources)      # the structured list, as described above
        row["src_root"] = fd.src_root                  # so a reader can show the source lines
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
