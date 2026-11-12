"""Turn an imported external-analyzer round into opinion-free review records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _ref(file: str, digest: str, rows: list[dict]) -> dict:
    if not rows:
        raise ValueError("cannot create an empty source reference")
    return {
        "file": file,
        "sha256": digest,
        "start_line": rows[0]["line"],
        "end_line": rows[-1]["line"],
        "text": [{"line": row["line"], "text": row["text"]} for row in rows],
    }


def _contiguous_refs(lines: list[dict], hashes: dict[str, str]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for row in lines:
        grouped.setdefault(row["file"].replace("\\", "/"), []).append(row)
    refs = []
    for file, rows in grouped.items():
        rows.sort(key=lambda row: row["line"])
        chunk: list[dict] = []
        for row in rows:
            if chunk and row["line"] != chunk[-1]["line"] + 1:
                refs.append(_ref(file, hashes[file], chunk))
                chunk = []
            chunk.append(row)
        if chunk:
            refs.append(_ref(file, hashes[file], chunk))
    return refs


def build(round_dir: Path, out_dir: Path) -> int:
    if out_dir.exists():
        raise ValueError(f"output directory already exists; choose a fresh path: {out_dir}")
    findings_path = round_dir / "findings.json"
    if not findings_path.is_file():
        raise ValueError(f"missing findings.json: {findings_path}")
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    if not isinstance(findings, dict):
        raise ValueError("findings.json must contain an object")
    records = []
    for fingerprint, row in findings.items():
        provenance = row.get("analysis_provenance") or {}
        evidence = row.get("backend_evidence") or {}
        lines = evidence.get("lines") or []
        hashes = {item["path"].replace("\\", "/"): item["sha256"]
                  for item in evidence.get("files", [])
                  if isinstance(item, dict) and item.get("path") and item.get("sha256")}
        primary = next((item for item in lines
                        if item.get("file") == row.get("file") and item.get("line") == row.get("line")), None)
        if primary is None:
            raise ValueError(f"missing primary evidence for {fingerprint}")
        primary_file = primary["file"].replace("\\", "/")
        if primary_file not in hashes:
            raise ValueError(f"missing source hash for {fingerprint}")
        context_refs = _contiguous_refs(lines, hashes)
        candidate_ref = _ref(primary_file, hashes[primary_file], [primary])
        limitations = [
            "本记录只提供命中位置附近的源码窗口，没有独立恢复完整控制流或调用关系。",
            "本记录没有运行目标代码，也没有证明输入控制、有效防护或可利用性。",
        ]
        status = "not_run"
        record = {
            "schema": "agentaudit-review-record-v1",
            "id": f"external-{fingerprint}",
            "project": row.get("project", "external-project"),
            "candidate": {
                "file": primary_file,
                "line": row.get("line"),
                "language": row.get("language", "text"),
                "kind": "external_analysis_result",
                "sink_name": "",
                "rule": row.get("rule", ""),
            },
            "candidate_source": [candidate_ref],
            "expected_material": [{"source": ref, "retrieved": True} for ref in context_refs],
            "collected_evidence": [],
            "source_review": {"reviewed_facts": []},
            "static_observations": {
                "status": status,
                "observations": [],
                "limitations": limitations,
                "scope": "backend-declared source window; external rule result only",
            },
            "open_questions": [
                "外部规则命中的语义条件是否在本项目上下文中成立？",
                "该位置的输入是否可由不可信来源控制？",
                "是否存在运行时绑定、防护或权限边界使该结果不构成问题？",
                f"外部分析器来源版本状态为 {provenance.get('source_version_status', 'unknown')}，需要人工确认其适用范围。",
            ],
        }
        records.append(record)
    # Validate every candidate before creating output, so a later invalid record
    # cannot leave a partial batch that looks like a complete review set.
    if not records:
        raise ValueError("no external findings to convert")
    out_dir.mkdir(parents=True, exist_ok=False)
    for ordinal, record in enumerate(records, 1):
        destination = out_dir / f"case-{ordinal:03d}.json"
        destination.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    written = len(records)
    print(f"wrote {written} external review records to {out_dir}")
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agentaudit review-records", description=__doc__)
    parser.add_argument("round", type=Path, help="round directory holding findings.json and backend evidence")
    parser.add_argument("--out", type=Path, required=True,
                        help="directory for the per-case records; it must not exist yet")
    args = parser.parse_args(argv)
    try:
        build(args.round, args.out)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"build_external_review_records: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
