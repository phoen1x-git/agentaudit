# -*- coding: utf-8 -*-
"""内核 · 契约投影层 —— 把一条 Finding（轮次里的 findings.json 一行）变成一条 candidates/v1。

★ 为什么单独一个模块：`candidates.jsonl` 是 agentaudit 与 agentaudit-verify 之间**唯一**的耦合。
  写这个格式的地方只能有一处，否则两处会分叉，而分叉的代价是下游拿错的版本号去追案。
  这一处要能被 `schemas/candidates.v1.json` 单独核对，不需要读别的代码。

★ 这一层只做投影：不扫描（扫描在 core/static_frontend.py 与 tools/），不判定（判定在 core/llm_judge.py）。
  候选里**不许**出现判定结果 —— 判定属于另一份契约 verdicts/v1。

★ 两条容易做错、修起来很贵的规矩：
  1. `candidate_id` 只依赖位置和函数名，不含规则号、不含判定。改算法 = 2747 条历史候选 id 全变，不可逆。
  2. `sink.func` 取调用表达式**末段**（`subprocess.Popen` → `Popen`），点分名进 `sink.qualname`。
     定这条是为了两个后端切法一致，否则同一处会得到两个 id。

★ 取不到的字段一律**不写**，不拿占位符凑：qualname 缺省＝没解析出来，不等于"没有"。
  唯一的例外是 `sink.arg_index`，契约规定取不到写 -1。
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SCHEMA = "candidates/v1"

ENTRY_KINDS = ("http", "cli", "mcp", "library")
ENTRY_AUTH = ("none", "required", "unknown")
ENTRY_EXPOSURE = ("high", "medium", "low", "unknown")
# 入口薄、实现厚：同仓库里把候选文件接进去的那个入口，只能是这三类（库接库没有意义）
SIBLING_KINDS = ("http", "cli", "mcp")
SIBLING_VIA = ("import", "same_package")
SIBLING_STRENGTH = ("strong", "weak")
TRACE_LEVELS = ("full", "window", "none")

# 版本取不到就写四十个 0（git 里"不知道"的惯用写法）。编一个看着像的 sha 比说不知道更糟。
# 内容由 file_sha256 钉住，所以这一行仍然是可复现的。
UNKNOWN_COMMIT = "0" * 40
NO_FILE_HASH = "0" * 64

_ARG_RE = re.compile(r"arg(\d+)\s*:")


def candidate_id(repo: str, file: str, line: int, sink_func: str) -> str:
    """位置指纹。★ 算法冻结，见契约 §2.2。"""
    raw = f"{repo}|{file}|{int(line)}|{sink_func}"
    return "c1:" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def split_sink(name: str) -> tuple[str, str]:
    """`subprocess.Popen` -> (`Popen`, `subprocess.Popen`)；`eval` -> (`eval`, ``)。"""
    name = (name or "").strip()
    if not name:
        return "", ""
    if "." in name:
        return name.rsplit(".", 1)[-1], name
    return name, ""


def file_sha256(src_root, rel_path: str) -> str:
    """按扫描当时的文件算哈希。读不到给全 0，**不猜**。"""
    if not src_root:
        return NO_FILE_HASH
    try:
        return hashlib.sha256((Path(src_root) / rel_path).read_bytes()).hexdigest()
    except OSError:
        return NO_FILE_HASH


def source_line(src_root, rel_path: str, line: int) -> str:
    """取 sink 那一行的原文。★ 契约要求"不截断"，而 findings.json 里的 snippet 是被截到 160 字的，
    所以有源码根就回头读原文。"""
    if not src_root or not line:
        return ""
    try:
        with open(Path(src_root) / rel_path, encoding="utf-8", errors="replace") as fh:
            for i, text in enumerate(fh, 1):
                if i == int(line):
                    return text.strip()
    except OSError:
        return ""
    return ""


def rel_path(path: str, src_root=None) -> str:
    """把靶机上的绝对路径压成相对路径。

    findings.json 里的 guards_list 存的是 `C:/.../<靶>/server.py#1487:12` 这种绝对路径。
    直接写进候选文件，等于把本机目录结构带进产物；这类产物迟早会被贴进报告。
    """
    if not path:
        return ""
    p = path.replace("\\", "/")
    if src_root:
        root = str(src_root).replace("\\", "/").rstrip("/")
        if p.startswith(root + "/"):
            return p[len(root) + 1:]
    # 退一步：切掉绝对前缀里最长的一段"看起来像仓库根"的目录 —— 取最后一节之后的相对部分，
    # 但这个规则太脆，所以只在能明显切掉盘符/用户目录时用。
    m = re.search(r"/(?:Users|home|root|tmp)/[^/]+/(?:[^/]+/)*?(?=[^/]+/[^/]+$|$)", p)
    if m and "/" in p[m.end():]:
        return p[m.end():]
    parts = p.split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else p


def parse_arg_index(arg_src: str) -> int:
    """从 `arg0:local` / `arg0:param(base_url@models.py:144)` 里取危险参数的下标。

    一行里出现**多个不同下标**时返回 -1：那时"哪个是危险参数"不是我能在这一层判的。
    """
    idxs = {int(m.group(1)) for m in _ARG_RE.finditer(arg_src or "")}
    return idxs.pop() if len(idxs) == 1 else -1


def parse_trace(chain: str) -> list[str]:
    """`a@x.py->b@y.py->sink@/abs$$1:2$$3:4` -> `["a", "b", "sink"]`（外到内）。"""
    out = []
    for hop in (chain or "").split("->"):
        name = hop.split("@", 1)[0].strip()
        if name and name not in out:
            out.append(name)
    return out


def _one_line(s: str) -> str:
    """契约里这些字段是"一句话"，所以换行要压掉。arg_src 里真的带换行。"""
    return re.sub(r"\s+", " ", (s or "")).strip()


def _check(value: str, allowed: tuple[str, ...], field: str) -> str:
    if value not in allowed:
        raise ValueError(f"{field}={value!r} 不在 {allowed} 里")
    return value


def _entry_profile(prof: dict | None, entry_kind: str) -> dict:
    """入口形态段（契约 §2.5，**可选**）。

    ★ 为什么可选而不是必填：`entry.kind` 是"归一化成四类之一"，profile 是"判定参数"。
      判定参数要读源码才填得出（`core/entry_kind.py`），AST 前端在拿不到源码根时填不了。
      设成必填会让历史轮次与 20 条 golden 立刻不合法，那是拿代价换一个"看起来更严"的字段。
    ★ `kind` 在这里冗余一份，是为了让这一小段能单独校验 —— 但它必须与 `entry.kind` 一致，
      由 `selftest_contract.py` 的档 6 核，不靠约定。
    """
    if not prof:
        return {}
    pk = _check(prof.get("kind") or entry_kind, ENTRY_KINDS, "entry_profile.kind")
    if pk != entry_kind:
        # ★ 与其让消费者去核两个 kind 一不一致，不如在这里就不许写出来。
        #   出现过一次真实情况：人工 --entry-kind 覆盖了自动判，两者不同，
        #   那时正确的做法是**不写 profile**（见 tools/export_candidates.py），不是写一份拧的。
        raise ValueError("entry_profile.kind=%s 与 entry.kind=%s 不一致" % (pk, entry_kind))
    out = {
        "kind": pk,
        "reach": (prof.get("reach") or "").strip(),
        "exposure": _check(prof.get("exposure") or "unknown", ENTRY_EXPOSURE,
                           "entry_profile.exposure"),
        "who": (prof.get("who") or "").strip(),
    }
    sib = prof.get("sibling_entry")
    if sib and sib.get("kind"):
        via = _check(sib.get("via") or "", SIBLING_VIA, "entry_profile.sibling_entry.via")
        strength = _check(sib.get("strength") or "", SIBLING_STRENGTH,
                          "entry_profile.sibling_entry.strength")
        # 强弱与通过方式必须同档 —— 这两样冗余就是给消费者过滤用的，拧了等于两套话。
        if {"import": "strong", "same_package": "weak"}[via] != strength:
            raise ValueError(
                "sibling_entry.via=%s 与 strength=%s 不同档（import↔strong, same_package↔weak）"
                % (via, strength))
        if not (sib.get("evidence") or "").strip():
            # 没有原文就不是证据，只是猜测。弱证据有它固定的话术，强证据必须有那句 import。
            raise ValueError("sibling_entry 缺 evidence：说不出是哪一行 import 就不要写成强证据")
        s = {
            "kind": _check(sib.get("kind"), SIBLING_KINDS, "entry_profile.sibling_entry.kind"),
            "file": (sib.get("file") or "").replace("\\", "/"),
            "via": via,
            "strength": strength,
        }
        for k in ("evidence", "reach"):
            if sib.get(k):
                s[k] = _one_line(sib[k])
        if not s["file"]:
            raise ValueError("entry_profile.sibling_entry 缺 file")
        out["sibling_entry"] = s
    return {k: v for k, v in out.items() if v}


def from_row(row: dict, *, repo: str, commit: str, entry_kind: str,
             entry_auth: str = "unknown", entry_value: str = "",
             backend_name: str, backend_rule: str = "", backend_version: str = "",
             trace_level: str = "full", src_root=None,
             entry_profile: dict | None = None) -> dict:
    """一行 findings.json -> 一条候选。值不合法直接抛，交给调用方数出来。"""
    _check(entry_kind, ENTRY_KINDS, "entry.kind")
    _check(entry_auth, ENTRY_AUTH, "entry.auth")
    _check(trace_level, TRACE_LEVELS, "trace_level")

    rel = (row.get("file") or "").replace("\\", "/")
    line = int(row.get("line") or 0)
    func, qualname = split_sink(row.get("sink") or "")
    if not rel or line <= 0 or not func:
        raise ValueError(f"行不完整：file={rel!r} line={line} sink={row.get('sink')!r}")

    text = source_line(src_root, rel, line) or _one_line(row.get("snippet") or "")
    if not text:
        raise ValueError(f"{rel}:{line} 取不到 sink 那一行原文")

    rec: dict = {
        "schema": SCHEMA,
        "candidate_id": candidate_id(repo, rel, line, func),
        "repo": repo,
        "commit": commit,
        "file": rel,
        "file_sha256": file_sha256(src_root, rel),
        "line": line,
        "sink": {"func": func, "arg_index": parse_arg_index(row.get("arg_src") or "")},
        "sink_call_text": text,
        "entry": {"kind": entry_kind, "auth": entry_auth},
        "backend": {"name": backend_name,
                    "rule_id": backend_rule or (row.get("rule") or "")},
        "trace_level": trace_level,
    }
    if qualname:
        rec["sink"]["qualname"] = qualname
    if entry_value:
        rec["entry"]["value"] = entry_value
    if backend_version:
        rec["backend"]["version"] = backend_version

    # ---- 可选段：只写后端真的看到的东西 ----
    static: dict = {}
    arg_src = _one_line(row.get("arg_src") or "")
    if arg_src:
        static["arg_source"] = arg_src
    guards = [_one_line(g) for g in (row.get("guards_list") or []) if _one_line(g)]
    if guards:
        static["guards"] = [
            "if 测试 @ " + rel_path(g.split("#", 1)[0], src_root).split("/")[-1]
            + (":" + g.split("#", 1)[1].split(":")[0] if "#" in g else "")
            for g in guards]
    if static:
        rec["static"] = static

    trace = parse_trace(row.get("chain") or "")
    if trace:
        rec["evidence"] = {"trace": trace}

    prof = _entry_profile(entry_profile, entry_kind)
    if prof:
        rec["entry_profile"] = prof

    return rec


def collapse_by_id(records: list[dict]) -> tuple[list[dict], int]:
    """一个位置一行 —— 案子是按位置开的。

    同一行被多条规则命中是常态（demo 上 `eval(request.form["code"])` 一行同时被三条规则指到）。
    那是一个要查的地方，不是三个。保留 `backend.rule_id` 字典序最小的那条，让结果与检查顺序无关。
    被折掉的规则不丢，仍在 findings.json 里；候选文件允许在这一维上有损，不许损的是 id。
    """
    best: dict[str, dict] = {}
    for r in records:
        cid = r["candidate_id"]
        prev = best.get(cid)
        if prev is None or str(r.get("backend", {}).get("rule_id", "")) < \
                str(prev.get("backend", {}).get("rule_id", "")):
            best[cid] = r
    return [best[k] for k in sorted(best)], len(records) - len(best)


def write_jsonl(path, records: list[dict]):
    """按 candidate_id 排序、UTF-8 无 BOM、一行一个。id 重复直接报错，不替调用方选。"""
    ids = [r["candidate_id"] for r in records]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"输出里有重复 candidate_id：{sorted(dupes)[:3]}")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for r in sorted(records, key=lambda x: x["candidate_id"]):
            fh.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
    return p


def read_jsonl(path) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{n}: 不是 JSON（{e}）") from e
    return out
