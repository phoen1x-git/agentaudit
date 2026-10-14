"""单列重跑 ai_verdict=error 的条目（截断被抹掉的那些）。

背景（`core/llm_judge.py:134-143`）：
  - 默认 max_tokens=2000，推理模型偶尔写超 → finish_reason=length → RuntimeError；
  - 代码会升配到 8000 重试一次，仍失败才记成 `error`；
  - ★ 截断**有随机性**（同一条这轮截断、隔会儿单独跑就过）。
→ 所以 `error` 条目**不是"判了没洞"**，是"根本没判"。必须单列并重跑。

用法：
    python tools/rejudge_errors.py --rounds round-a1b-ctxoff,round-a1b-ctxon
    python tools/rejudge_errors.py                # 自动扫所有轮
    python tools/rejudge_errors.py --mt 8000      # 强制额度（默认 8000，避开截断）
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import core.finding as F  # noqa: E402
from core import llm_judge as LJ  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTDIR = os.path.join(ROOT, "data", "target_pool")


def _mk_finding(rec: dict) -> "F.Finding":
    """按 finding.py 的字段名把一条 findings.json 记录还原成 Finding。"""
    fd = F.Finding(project=rec.get("project", ""))
    fd.fingerprint = rec.get("fingerprint", "")
    fd.rule = rec.get("rule", "")
    fd.sink_func = rec.get("sink", "")          # findings.json 里叫 sink
    fd.sink_uri = rec.get("file", "")           # findings.json 里叫 file
    fd.sink_line = int(rec.get("line") or 0)
    fd.depth = int(rec.get("depth") or 0)
    fd.variants = int(rec.get("variants") or 1)
    fd.entry = rec.get("entry", "")
    fd.entries = rec.get("entries", "")
    fd.snippet = rec.get("snippet", "")
    fd.chain = rec.get("chain", "")
    gl = rec.get("guards_list") or []
    fd.guards = list(gl)
    fd.arg_sources = rec.get("arg_sources") or []
    # ★ src_root：判定层取源码要用。从 targets*.yml 的短名→src 映射补。
    try:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        from sample_false_negatives import _SRC_MAP  # noqa
        proj = (rec.get("project") or "").lower()
        fd.src_root = _SRC_MAP.get(proj, "")
    except Exception:
        fd.src_root = ""
    return fd


def collect_errors(rounds: list[str]) -> list[tuple[str, dict]]:
    out = []
    seen = set()
    for tag in rounds:
        f = os.path.join(ROOT, "out", tag, "findings.json")
        if not os.path.exists(f):
            continue
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        for fp, r in d.items():
            if (r.get("ai_verdict") or "").strip() != "error":
                continue
            if fp in seen:
                continue
            seen.add(fp)
            out.append((tag, r))
    return out


def discover_rounds() -> list[str]:
    return sorted(os.path.basename(os.path.dirname(f))
                  for f in glob.glob(os.path.join(ROOT, "out", "round-*", "findings.json")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", default="")
    ap.add_argument("--mt", default="8000")
    ap.add_argument("--tag", default="20261011")
    a = ap.parse_args()

    rounds = a.rounds.split(",") if a.rounds else discover_rounds()
    errs = collect_errors(rounds)
    print(f"发现 error 条目 {len(errs)} 条")
    if not errs:
        return 0

    os.environ["AF_JUDGE_MT"] = str(a.mt)   # 强制额度，避开截断
    results = []
    for tag, rec in errs:
        fd = _mk_finding(rec)
        cache: dict = {}
        try:
            r = LJ.judge_one(fd, cache, tag=f"rejudge-{a.tag}")
            LJ._apply(fd, r)
            verdict = fd.ai_verdict
            conf = fd.ai_confidence
            reason = fd.ai_reason
            note = "OK"
        except Exception as e:
            verdict, conf, reason, note = "error", 0.0, f"{type(e).__name__}: {e}"[:200], "STILL_FAILED"
        results.append({
            "fingerprint": rec.get("fingerprint"),
            "project": rec.get("project"),
            "file": rec.get("file"),
            "line": rec.get("line"),
            "sink": rec.get("sink"),
            "orig_round": tag,
            "new_verdict": verdict,
            "new_conf": conf,
            "new_arg_source": fd.arg_source,
            "new_reason": reason,
            "note": note,
        })
        print(f"  {rec.get('project'):<18} {os.path.basename(rec.get('file',''))}:{rec.get('line'):<5} "
              f"→ {verdict:11} conf={conf:.2f} asrc={fd.arg_source}  [{note}]")
        if verdict != "error":
            print(f"      理由: {reason[:120]}")

    os.makedirs(OUTDIR, exist_ok=True)
    out = os.path.join(OUTDIR, f"error_rejudge_{a.tag}.json")
    json.dump({"_meta": {"mt": a.mt, "n": len(errs)}, "results": results},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\nJSON: {out}")
    changed = [r for r in results if r["note"] == "OK"]
    print(f"重跑成功 {len(changed)}/{len(errs)}；仍失败 {len(errs)-len(changed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
