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
    ap = argparse.ArgumentParser(description="把一轮扫描投影成 candidates/v1（JSONL）")
    ap.add_argument("--round", required=True, help="轮次目录，里面要有 findings.json")
    ap.add_argument("--repo", required=True, help="owner/name，靶的仓库身份")
    ap.add_argument("--commit", default="", help="40 位 sha；缺省从 --src-root 的 git 取，取不到写全 0")
    ap.add_argument("--src-root", default="", help="靶源码根，用来读 sink 原文和算 file_sha256")
    ap.add_argument("--entry-kind", default="", choices=("",) + C.ENTRY_KINDS,
                    help="人工指定整轮的入口形态（覆盖自动判）。不填则逐条按候选所在文件判，需要 --src-root")
    ap.add_argument("--entry-auth", default="unknown", choices=C.ENTRY_AUTH)
    ap.add_argument("--entry-value", default="", help="http 给 'POST /chat'；mcp 给 tool 名")
    ap.add_argument("--only-project", default="",
                    help="一轮里混了多个项目时，只取这一个（其余丢弃）。不填则多项目直接报错")
    ap.add_argument("--trace-level", default="full", choices=C.TRACE_LEVELS)
    ap.add_argument("--backend-name", default="codeql")
    ap.add_argument("--backend-version", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    rd = Path(a.round)
    fj = rd / "findings.json"
    if not fj.exists():
        raise SystemExit(f"{fj} 不存在：--round 要指到轮次目录")

    rows = json.loads(fj.read_text(encoding="utf-8"))
    if not isinstance(rows, dict):
        raise SystemExit(f"{fj} 不是 {{fingerprint: row}} 结构")

    projects = sorted({(v.get("project") or "") for v in rows.values()} - {""})
    if a.only_project:
        rows = {k: v for k, v in rows.items() if (v.get("project") or "") == a.only_project}
        if not rows:
            raise SystemExit("--only-project %s 在这一轮里一条都没有" % a.only_project)
        projects = [a.only_project]
    if len(projects) > 1:
        raise SystemExit(
            "这一轮里有 %d 个项目：%s\n"
            "一轮 = 一个仓库，--repo 只能填一个。用 --only-project <名字> 只取其中一个，"
            "别让我替你猜归属。"
            % (len(projects), projects))

    commit = a.commit or git_commit(a.src_root)
    version = a.backend_version or kernel_version()
    src_root = a.src_root or None

    if not a.entry_kind and not src_root:
        raise SystemExit(
            "不给 --entry-kind 就必须给 --src-root：\n"
            "形态是按**候选所在文件**判的（core/entry_kind.py），没有源码判不了。\n"
            "要么补 --src-root 让它自动判，要么 --entry-kind 明说整轮都是哪一类。")

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
        print("[warn] 取不到 commit，写的是四十个 0（版本未知）", file=sys.stderr)
    if disagree:
        print("[warn] 有 %d 条人工指定的形态与自动判不一致（见 entry_kind_notes）" % disagree,
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
