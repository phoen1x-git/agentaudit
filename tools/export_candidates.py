# -*- coding: utf-8 -*-
"""把一轮扫描的候选写成 candidates.jsonl（契约 v1）。

    # 形态自动判（推荐）：给出源码根，逐条按候选所在文件判
    python tools/export_candidates.py \
        --round out/round-example \
        --repo owner/name --entry-auth none \
        --src-root ../sources/owner__name \
        --out out/_contract/example.jsonl

    # 形态人工指定（覆盖自动判）：只在自动判错、且你知道为什么时说
    python tools/export_candidates.py ... --entry-kind http

★ 数据源是**轮次目录里的 findings.json**，不是重新扫一遍。
  理由：契约要的是"某次扫描里的某一处"，重扫会换一份候选集，对不上账；
  而且历史轮次都在盘上，直接投影最便宜。

★ `--entry-kind` 从**必填**改成**可覆盖**。
  依据是 `core/entry_kind.py` —— 形态是**候选所在文件**的属性，不是仓库的属性，
  所以逐条判才对；以前一条命令一个 `--entry-kind` 给整轮，等于把"整个仓库是什么形态"
  这个本来就没有唯一答案的问题硬答一遍。
  ★ 判不出形态（文件不在源码根、解析失败）时**这一条不写进契约**，记进 skipped ——
    契约的四种形态都必填，塞一个 'unknown' 进去等于把"不知道"伪装成"判过了"。

★ 仍然不能从数据里推出来的东西，还是参数：
  - 入口要不要鉴权（--entry-auth）：判据不做这件事，它只数到 `auth_patterns` 有几处，
    "数到了"不等于"鉴权住了"，这一步得人看；
  - 靶的 repo 身份（--repo）：findings.json 里只有 project 短名，没有 owner。
  填错比不填更糟：错标签会静默变成下游的判定输入。

★ 一轮里混了多个项目时**直接报错退出**，不替调用方决定"这些行算谁的仓库"。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import candidates as C          # noqa: E402
from core import entry_kind as EK         # noqa: E402


def git_commit(path) -> str:
    if not path:
        return C.UNKNOWN_COMMIT
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return C.UNKNOWN_COMMIT
    sha = (out.stdout or "").strip()
    ok = out.returncode == 0 and len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)
    return sha if ok else C.UNKNOWN_COMMIT


def kernel_version() -> str:
    try:
        from core import __version__ as v      # 私有副本的 core/__init__ 未必有
        return str(v)
    except Exception:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="agentaudit candidates",
        description="project one scan round into candidates/v1 (JSONL)")
    ap.add_argument("round", nargs="?", default="",
                    help="a round directory, e.g. out/round-my-round")
    ap.add_argument("--round", dest="round_opt", default="",
                    help="the same round directory, as an option (the older form)")
    ap.add_argument("--repo", required=True,
                    help="owner/name: the repository identity of the target")
    ap.add_argument("--commit", default="",
                    help="40-character sha; default: read from git at --src-root, "
                         "or write all zeroes if that fails")
    ap.add_argument("--src-root", default="",
                    help="source root of the target: used to read the sink line and "
                         "compute file_sha256")
    ap.add_argument("--entry-kind", default=None, choices=C.ENTRY_KINDS,
                    help="set the entry kind for the whole round, overriding the automatic "
                         "judgement. Omit it and the kind is decided per candidate from the "
                         "file it sits in, which needs --src-root")
    ap.add_argument("--entry-auth", default="unknown", choices=C.ENTRY_AUTH,
                    help="whether that entry point requires authentication; used only "
                         "when --entry-kind is set")
    ap.add_argument("--entry-value", default="",
                    help="for http, something like 'POST /chat'; for mcp, the tool name")
    ap.add_argument("--only-project", default="",
                    help="when a round mixes several projects, keep only this one and drop the "
                         "rest. Left empty, a mixed round is an error")
    ap.add_argument("--trace-level", default="full", choices=C.TRACE_LEVELS,
                    help="how much of the call chain to record: full, window only, or none")
    ap.add_argument("--backend-name", default="codeql",
                    help="which analyzer produced the findings (default: codeql)")
    ap.add_argument("--backend-version", default="",
                    help="that analyzer's version, if you know it")
    ap.add_argument("--out", required=True,
                    help="where to write candidates.jsonl (the file other tools read)")
    a = ap.parse_args()

    if not (a.round or a.round_opt):
        ap.error("a round directory is required, e.g. "
                 "agentaudit candidates out/round-my-round --repo owner/name --out c.jsonl")
    rd = Path(a.round or a.round_opt)
    fj = rd / "findings.json"
    if not fj.exists():
        raise SystemExit(f"{rd} is not a round directory: no findings.json inside it")

    rows = json.loads(fj.read_text(encoding="utf-8"))
    if not isinstance(rows, dict):
        raise SystemExit(f"{fj} is not a {{fingerprint: row}} mapping")

    projects = sorted({(v.get("project") or "") for v in rows.values()} - {""})
    if a.only_project:
        rows = {k: v for k, v in rows.items() if (v.get("project") or "") == a.only_project}
        if not rows:
            raise SystemExit("--only-project %s matched nothing in this round" % a.only_project)
        projects = [a.only_project]
    if len(projects) > 1:
        raise SystemExit(
            "this round holds %d projects: %s\n"
            "A round is one repository and --repo takes one name. Use --only-project <name> "
            "to keep one of them; the file cannot carry an identity I would have to guess."
            % (len(projects), projects))

    commit = a.commit or git_commit(a.src_root)
    version = a.backend_version or kernel_version()
    src_root = a.src_root or None

    if not a.entry_kind and not src_root:
        raise SystemExit(
            "without --entry-kind the round needs --src-root:\n"
            "the entry kind is a property of the file each candidate sits in "
            "(core/entry_kind.py), so it cannot be decided without the source.\n"
            "Add --src-root DIR to have it decided per candidate, or --entry-kind to state "
            "that the whole round is one of http, cli, mcp, library.")

    recs, skipped = [], []
    kinds: dict[str, int] = {}
    kind_notes: list[dict] = []
    disagree = 0
    for fp, row in rows.items():
        rel = (row.get("file") or "").replace("\\", "/")
        prof: dict = {}          # 入口形态段（可选，见 core/candidates.py::_entry_profile）
        if a.entry_kind:
            kind = a.entry_kind
            if src_root:            # 人工指定时也顺手对一下，判错不静默
                auto = EK.classify(src_root, rel)
                if auto.get("kind") in C.ENTRY_KINDS and auto["kind"] != kind:
                    disagree += 1
                    if len(kind_notes) < 4:
                        kind_notes.append({"file": rel, "manual": kind, "auto": auto["kind"],
                                           "reach": auto.get("reach", "")})
                    # ★ 两者不一致时不写 profile：手工覆盖的意义就是"自动判错了"，
                    #   把判错的那份参数写进契约等于自相矛盾。宁可缺，不许拧。
                else:
                    prof = auto
        else:
            auto = EK.classify(src_root, rel)
            kind = auto.get("kind") or "unknown"
            if kind not in C.ENTRY_KINDS:
                skipped.append("%s: 判不出形态（%s%s）" % (
                    fp, kind, "：" + auto["why"] if auto.get("why") else ""))
                continue
            prof = auto
            if len(kind_notes) < 4:
                kind_notes.append({"file": rel, "auto": kind, "reach": auto.get("reach", "")})
        try:
            recs.append(C.from_row(
                row, repo=a.repo, commit=commit, entry_kind=kind,
                entry_auth=a.entry_auth, entry_value=a.entry_value,
                backend_name=a.backend_name, backend_version=version,
                trace_level=a.trace_level, src_root=src_root,
                entry_profile=prof))
            kinds[kind] = kinds.get(kind, 0) + 1     # 只数**写出去**的，不数试图写的
        except ValueError as e:
            skipped.append(f"{fp}: {e}")

    recs, collapsed = C.collapse_by_id(recs)
    out = C.write_jsonl(a.out, recs)

    print(json.dumps({
        "out": str(out), "n_rows": len(rows), "n_written": len(recs),
        "collapsed_same_position": collapsed, "skipped": len(skipped),
        "repo": a.repo, "commit": commit,
        "entry_kind_source": "manual" if a.entry_kind else "auto",
        "entry_kinds": kinds,
        "entry_kind_notes": kind_notes,
        "entry_kind_disagree": disagree,
        "n_without_file_hash": sum(1 for r in recs if r["file_sha256"] == C.NO_FILE_HASH),
        "n_arg_index_known": sum(1 for r in recs if r["sink"].get("arg_index", -1) >= 0),
        "n_with_entry_profile": sum(1 for r in recs if r.get("entry_profile")),
        "n_with_sibling_entry": sum(1 for r in recs
                                    if (r.get("entry_profile") or {}).get("sibling_entry")),
        "n_sibling_strong": sum(1 for r in recs
                                if ((r.get("entry_profile") or {}).get("sibling_entry") or {}
                                    ).get("via") == "import"),
        "skip_reasons": skipped[:3],
    }, ensure_ascii=False, indent=1))
    if commit == C.UNKNOWN_COMMIT:
        print("[warn] no commit available; writing forty zeroes (version unknown)",
          file=sys.stderr)
    if disagree:
        print("[warn] %d hand-set kind(s) disagree with the automatic judgement "
              "(see entry_kind_notes)" % disagree,
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
