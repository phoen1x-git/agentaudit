"""内核 · CodeQL 静态前端。

职责（只有这一件事）：
    已建好的 CodeQL 库  ──跑规则──▶  SARIF  ──解析──▶  Finding 列表

★ 这一层**不判断漏洞**。它只负责"把源码里的可疑调用点找出来"。
★ 内核的一份代码：A1 全开跑；B 论文靠开关的组合跑对比。这里的开关见 core/config/。

用法（内核内部）：
    from core.static_frontend import run_db_to_findings
    fnd = run_db_to_findings(db_dir, project="example", on_log=print)
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Optional

from . import finding as F
from . import cfg as CFG

# ----------------------------------------------------------------------------
# CodeQL 可执行文件定位（默认在本项目 _tools 下；可用环境变量覆盖）
# ----------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent          # .../agentaudit/core
_PROJ = _HERE.parent                              # .../agentaudit
_WORKSPACE = _PROJ.parent                         # the directory the checkout sits in


def _default_codeql() -> Path:
    """Where `scripts/setup.sh` puts the CLI: `<checkout>/_tools/codeql`.

    ★ It used to point one level above the checkout, which was right in the directory this
      code was extracted from and wrong everywhere else. The failure was quiet and expensive:
      setup.sh installed CodeQL into the repository, the frontend looked for it in the parent
      directory, did not find it, and fell back to the offline path. The scan finished, said
      nothing, and simply found less. `agentaudit doctor` now prints the path it will use, so
      the two can be compared.
    """
    base = _PROJ / "_tools" / "codeql"
    for name in ("codeql.exe", "codeql"):
        candidate = base / name
        if candidate.exists():
            return candidate
    return base / ("codeql.exe" if os.name == "nt" else "codeql")


DEFAULT_CODEQL = _default_codeql()
# ★★ 优先用**我们自己的包**（core/ql，由 `core/gen_ql.py` 从 sinks.yml 生成）。
#    没有它才退回论文原包 —— 那时 sinks.yml 只是个摆设。
_KERNEL_QL = _PROJ / "core" / "ql"
DEFAULT_QL_DIR = _KERNEL_QL if _KERNEL_QL.exists() else (_WORKSPACE / "agentfuzz-official" / "ql")
# ★★ ：这三条查询的名字**只能有一个主人**（`core/gen_ql.py` 写它们、也生成它们）。
#    以前这里复述了一遍列表，于是"加一条查询"要改两个地方 —— 漏一处就会出现
#    "QL 生成了但前端不跑它"，而两边都不报错。`test_the_query_list_has_one_owner` 守的就是这条。
#    ★ 连注释里都不许出现那几个文件名：那条测试查的是**文件全文**，写注释也算复述。
from .gen_ql import QUERIES   # noqa: E402  （放在这里是为了让它紧挨着 DEFAULT_QL_DIR，读起来是一件事）
# ★ 我们自带的跨过程实参来源查询（开关 dataflow-argsource）。
#   单独跑、单独解析 —— 它的输出格式与上面三条完全不同（见 core/ql_src/）。
ARG_QUERY = "get_arg_source.ql"


def codeql_exe() -> str:
    return os.environ.get("AF_CODEQL", str(DEFAULT_CODEQL))


def ql_dir() -> str:
    return os.environ.get("AF_QL_DIR", str(DEFAULT_QL_DIR))


def argsrc_enabled() -> bool:
    """开关 dataflow-argsource（默认开；`--no-dataflow` 会设环境变量关掉）。"""
    return os.environ.get("AF_NO_DATAFLOW", "0") != "1"


# ----------------------------------------------------------------------------
# 1) 跑查询 → SARIF
# ----------------------------------------------------------------------------
def run_analyze(db_dir: str, out_path: str, on_log: Callable[[str], None] = print,
                queries: Optional[list[str]] = None, ql_root: Optional[str] = None) -> bool:
    """对已建的 CodeQL 库跑规则，输出 CSV。返回是否成功。

    ★ 从 SARIF 换成 CSV：查询现在吐 JSON，而 SARIF 的 message 是
      .NET 风格格式串 —— `{` 会被转义成 `{{`、`[` 会加反斜杠，JSON 到 Python 侧
      已经认不出来了。CSV 把每一列原样写出来，csv 模块读回来就是原文。
      对外的 `results.sarif` 不受影响：那是 `tools/to_sarif.py` 从 findings 重新生成的。

    ★ `ql_root` 是 为扩语言加的：Python 的查询在 `core/ql/`，
      JS 的在 `core/ql/js/`（依赖不同的 ql 包，必须分开）。不传就是 Python 那一套，
      老调用点一个字都不用改。
    """
    exe = codeql_exe()
    ql = ql_root or ql_dir()
    if not os.path.exists(exe):
        on_log(f"[FAIL] codeql not found: {exe}")
        return False
    names = QUERIES if queries is None else queries
    qpaths = [os.path.join(ql, q) for q in names]
    missing = [q for q in qpaths if not os.path.exists(q)]
    if missing:
        on_log(f"[FAIL] missing rule file(s): {missing}")
        return False
    cmd = [exe, "database", "analyze", db_dir, *qpaths,
           "--format=csv", f"--output={out_path}", f"--search-path={ql}"]
    on_log("[cmd] " + " ".join(f'"{c}"' if " " in c else c for c in cmd[1:]))
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        on_log(f"[FAIL] codeql exited {p.returncode}")
        tail = (p.stdout or "")[-1500:] + (p.stderr or "")[-1500:]
        on_log(tail)
        return False
    on_log("[ok] results written to " + out_path)
    return True


# ----------------------------------------------------------------------------
# 1b) 跨过程实参来源 → {(相对路径, 行): [ {i, kind, src_file, src_line, src_text} ]}
# ----------------------------------------------------------------------------
def run_and_parse_argsrc(db_dir: str, project: str,
                         on_log: Callable[[str], None] = print) -> dict:
    """跑 get_arg_source.ql 并把结果按 (相对路径, sink行) 索引。

    ★ 失败/关闭时返回空 dict —— **不抛异常**：这是"附加证据"，不该让整轮挂掉。
    """
    if not argsrc_enabled():
        return {}
    ql = ql_dir()
    if not os.path.exists(os.path.join(ql, ARG_QUERY)):
        on_log(f"[argsrc] skipped: the pack has no {ARG_QUERY} "
           "(--no-dataflow turns it off explicitly)")
        return {}
    tmp = os.path.join(tempfile.gettempdir(), f"af_{project}_argsrc.csv")
    if not run_analyze(db_dir, tmp, on_log, queries=[ARG_QUERY]):
        on_log("[argsrc] ★ the query failed, so this round has no argument-source "
           "evidence; triage will report unknown as it did before")
        return {}
    prefix = _read_src_prefix(db_dir)
    idx: dict = {}
    try:
        fh = open(tmp, newline="", encoding="utf-8", errors="replace")
    except OSError:
        return {}
    with fh:
        for row in csv.reader(fh):
            if len(row) < 6:
                continue
            uri = row[4] or ""
            line = row[5] or "0"
            # CSV 的路径列是"相对源根"，且带前导斜杠；SARIF 那边是绝对路径
            rel = _rel(uri, prefix) if os.path.isabs(uri) else uri.lstrip("/")
            # ★★★ 修：**一条 CSV 行的 message 里可能有多个实参**。
            #   CodeQL 把「同一定位点的多条 select 结果」合并进同一个 message，用真换行分隔：
            #       "local@@0@@1609@@static_dir@@⏎param@@1@@1609@@path@@server.py@@1608@@path"
            #   而 `csv.reader` 会把整段读成**一个** cell（引号内的换行合法），
            #   所以按 `@@` 直接切会得到 13 段，`parts[:7]` 只取到第一个实参 —— 后面的**静默丢掉**。
            #   实测代价：某个样本 `server.py` 里的 `os.path.join(static_dir, path)`，
            #   `arg1`（`path`，外部可控的那个）一直没有落盘，`arg0`（`static_dir`，本地常量）占了位。
            #   这就是"实参来源看着全是 local"的一半原因 —— 不是追不到，是**报上来又被自己扔了**。
            for seg in (row[3] or "").splitlines():
                parts = seg.split("@@")
                if len(parts) < 7:
                    continue
                idx.setdefault((rel, int(line) if line.isdigit() else 0), []).append({
                    "i": int(parts[1]) if parts[1].isdigit() else -1,
                    "kind": parts[0],
                    "arg_line": int(parts[2]) if parts[2].isdigit() else 0,
                    "arg_text": parts[3],
                    "src_file": parts[4],
                    "src_line": int(parts[5]) if parts[5].isdigit() else 0,
                    "src_text": parts[6],
                })
    on_log(f"[argsrc] argument-source evidence: {sum(len(v) for v in idx.values())} "
           f"row(s), "
           f"覆盖 {len(idx)} 个 sink 位置")
    return idx


# ----------------------------------------------------------------------------
# 2) SARIF → Finding
# ----------------------------------------------------------------------------
_DEPTH_RE = re.compile(r"^\[?(\d+)#")


def _read_src_prefix(db_dir: str) -> str:
    """从 codeql-database.yml 读源码根（用于把绝对路径转相对路径）。"""
    yml = Path(db_dir) / "codeql-database.yml"
    try:
        for line in yml.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("sourceLocationPrefix:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return ""


def _rel(abs_path: str, prefix: str) -> str:
    p = abs_path.replace("\\", "/")
    if prefix:
        pfx = prefix.replace("\\", "/").rstrip("/")
        if p.startswith(pfx):
            p = p[len(pfx):]
    return p.lstrip("/")


def _parse_payload(text: str) -> dict:
    """一行查询输出（JSON）→ 字典。认不出来就返回空 dict，由调用方决定怎么处置。"""
    text = (text or "").strip()
    if not text:
        return {}
    try:
        d = json.loads(text)
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def _loc_text(item: dict) -> str:
    """一个位置 → `函数名#路径#起行:起列#止行:止列`。沿用 guards 字段的既有写法。"""
    return "%s#%s#%s:%s#%s:%s" % (
        item.get("function", ""), item.get("file", ""),
        item.get("line", 0), item.get("col", 0),
        item.get("end_line", 0), item.get("end_col", 0))


def _chain_text(payload: dict) -> str:
    """重建成 `深度#入口@文件->...->sink@文件$行:列$行:列`。

    ★ 这是 `Finding.chain` 的既有写法，判定层的提示词、报告、审阅页都在读它。
      换查询输出格式是一件事，换这个字段的写法是另一件事 —— 后者会动到判定，
      所以这里照旧拼，不趁机改。
    """
    hops = payload.get("hops") or []
    sink = payload.get("sink") or {}
    parts = ["%s@%s" % (h.get("function", ""), os.path.basename(h.get("file", "")))
             for h in hops]
    parts.append("%s@%s$$%s:%s$$%s:%s" % (
        sink.get("function", ""), sink.get("file", ""),
        sink.get("line", 0), sink.get("col", 0),
        sink.get("end_line", 0), sink.get("end_col", 0)))
    return "%s#%s" % (payload.get("depth", 0), "->".join(parts))


def parse_results(csv_path: str, project: str) -> list[F.Finding]:
    """CodeQL 的 CSV 结果 → Finding 列表。

    列序（CodeQL 固定）：元素文本 / 描述 / 严重度 / message / 文件 / 起行 / 起列 / 止行 / 止列。
    我们只认第 4 列（message = 查询吐的 JSON）。

    ★ 一格多行：同一个 source 有多条链时，CodeQL 把它们的 message 用换行拼在**同一个单元格**里。
      所以这里要 `splitlines()` 再逐行解析，一行一个 Finding —— 原来按 SARIF 取
      `split("\\n", 1)[0]` 只留第一条，换成 CSV 之后那样会静默丢结果。
    认不出的行计数上报，不静默跳过。
    """
    out: list[F.Finding] = []
    bad = 0
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.reader(fh):
            if len(row) < 5:
                continue
            for line in (row[3] or "").splitlines():
                payload = _parse_payload(line)
                if not payload:
                    if line.strip():
                        bad += 1
                    continue
                sink = payload.get("sink") or {}
                hops = payload.get("hops") or []
                out.append(F.Finding(
                    project=project,
                    rule=payload.get("rule") or "unknown",
                    sink_func=sink.get("function") or "",
                    sink_uri=sink.get("file") or "",
                    sink_line=int(sink.get("line") or 0),
                    sink_col=int(sink.get("col") or 0),
                    entry=(hops[0].get("function") if hops else ""),
                    depth=int(payload.get("depth") or 0),
                    guards=[_loc_text(g) for g in (payload.get("guards") or [])],
                    chain=_chain_text(payload),
                ))
    if bad:
        print("[parse] ★ %d row(s) are not this query version's output "
              "(JSON parse failed); skipped" % bad)
    return out


def finalize(findings: list[F.Finding], db_dir: str, filters: dict,
             on_log: Callable[[str], None] = print,
             argsrc: Optional[dict] = None,
             src_fallback: Optional[str] = None) -> list[F.Finding]:
    prefix = _read_src_prefix(db_dir)
    # ★★ 修：库内的 `sourceLocationPrefix` 是**建库那一刻**的绝对路径。
    #    工作区搬过家之后（换了目录、换了机器），这个前缀就指向不存在的目录，
    #    而它被用来做三件事：判入口形态（entry_kind.classify）、读源码窗口（_read_line）、
    #    记 `src_root`。三件事一起静默失效 —— 实测某一轮 136 条**全部**判成
    #    `kind=unknown / why=文件不存在`，看起来像"形态判不出来"，其实是"文件都打不开"。
    #    这是"失败伪装成结论"的又一例：判不出形态会让人以为工具能力不够，
    #    而真相是一行路径过期。所以这里**不许静默**：前缀不可用时必须出一行日志。
    prefix_note = ""
    _db_prefix = prefix
    if not prefix or not Path(prefix).is_dir():
        why = "库内没有源码前缀" if not prefix else f"库内源码前缀失效（{prefix}）"
        if src_fallback and Path(src_fallback).is_dir():
            prefix = str(Path(src_fallback).resolve())
            prefix_note = f"{why} → 改用配置的 src：{prefix}"
        else:
            prefix_note = f"{why}，且没有配置可用的 src ⇒ 形态与源码窗口都判不了"
    if prefix_note:
        on_log("[source-root] " + prefix_note)
    # ★★ 并入：每条 finding 都记下「这份库对应的源码是不是当前源码」。
    #    值只有三种，含义写死，不许含糊：
    #      matched    —— 库是用当前这份源码建的，行号可信；
    #      mismatch   —— 源码改过了，行号可能已经偏移，判定前要重建；
    #      unverified —— 没有标记或标记坏了，**不能说它是对的**。
    #    这个字段会一路进 `analysis_provenance` → `judge_evidence.build()` 的
    #    `blocking_gaps` → `triage_contract.apply_policy` 的降级理由。
    from .source_version import database_status
    provenance = database_status(Path(db_dir), prefix)
    if prefix_note:
        # 让下游（判定层 / 案卷 / 报告）能看出"这份 src_root 不是库自己记的那个"
        provenance["src_prefix"] = {"db": _db_prefix, "used": prefix, "note": prefix_note}
    on_log(f"[source-version] {provenance['source_version_status']}")
    # ★★ 入口形态：按**候选所在文件**判（不是按仓库 import 判 —— 第五步踩过，
    #    按 import 判会把四类里的三类全判成 http）。同一个文件只判一次。
    from . import entry_kind as EK
    profiles: dict[str, dict] = {}
    kept: list[F.Finding] = []
    dropped = 0
    with_src = 0
    for fd in findings:
        # ★★ 两套前缀不能混用（实测踩到）：
        #    `fd.sink_uri` 来自 CodeQL 结果，坐标系是**建库时**的根（`_db_prefix`）；
        #    而"文件现在在哪儿"是 `prefix`（可能是配置兜住的 src）。
        #    拿新根去切旧绝对路径切不动 → rel 原样返回绝对路径 → 判形态一律"文件不存在"、
        #    实参证据一律匹配不上（实测：形态 unknown=136、argsrc 4→0）。
        #    所以**转相对用旧根，读文件用新根**。
        _uri_root = _db_prefix or prefix
        rel = _rel(fd.sink_uri, _uri_root) if os.path.isabs(fd.sink_uri) else fd.sink_uri
        fd.sink_uri = rel
        if CFG.path_is_filtered(rel, filters):
            dropped += 1
            continue
        fd.src_root = prefix
        fd.analysis_provenance = dict(provenance)
        if rel not in profiles:
            try:
                profiles[rel] = EK.classify(prefix, rel) if prefix else {}
            except Exception as exc:              # noqa: BLE001
                profiles[rel] = {"kind": "unknown", "why": f"判形态出错：{type(exc).__name__}"}
        fd.entry_profile = profiles[rel]
        fd.snippet = _read_line(prefix, rel, fd.sink_line)
        fd.fingerprint = F.make_fingerprint(fd.project, rel, fd.sink_func, fd.snippet)
        if argsrc:
            hit = argsrc.get((rel, fd.sink_line)) or argsrc.get((fd.sink_uri, fd.sink_line))
            if hit:
                fd.arg_sources = hit
                with_src += 1
        kept.append(fd)
    if dropped:
        on_log(f"[filter] the path filter dropped {dropped}")
    if argsrc:
        on_log(f"[argsrc] {with_src} finding(s) got argument-source evidence")
    if kept:
        from collections import Counter
        kinds = Counter((f.entry_profile or {}).get("kind", "unknown") for f in kept)
        on_log("[entry] entry kinds: " + " / ".join("%s=%d" % (k, v) for k, v in kinds.most_common())
               + "（按候选所在文件判，不是按仓库 import 判）")
        # ★ 入口薄、实现厚：这些候选文件本身是库，但同仓库的入口文件把它接进去了。
        #   强证据（有 import 语句）和弱证据（只是同目录）分开数，不许混成一个数。
        sibs = [s for s in ((f.entry_profile or {}).get("sibling_entry") for f in kept) if s]
        if sibs:
            strong = sum(1 for s in sibs if s.get("via") == "import")
            by_kind = Counter(s.get("kind", "?") for s in sibs)
            on_log("[entry] %d of them are library files pulled in by an entry point "
           "(import: strong %d / same directory: weak %d): %s"
                   % (len(sibs), strong, len(sibs) - strong,
                      " / ".join("%s=%d" % (k, v) for k, v in by_kind.most_common())))
    return kept


def _read_line(prefix: str, rel: str, line: int) -> str:
    if not prefix or not rel or not line:
        return ""
    p = Path(prefix) / rel
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for i, s in enumerate(fh, 1):
                if i == line:
                    return s.rstrip("\n")
    except OSError:
        return ""
    return ""


# ----------------------------------------------------------------------------
# 4) 一次到位
# ----------------------------------------------------------------------------
def run_db_to_findings(db_dir: str, project: str,
                       on_log: Callable[[str], None] = print,
                       src_fallback: Optional[str] = None) -> list[F.Finding]:
    filters = CFG.load_filters()
    tmp = os.path.join(tempfile.gettempdir(), f"af_{project}.csv")
    if not run_analyze(db_dir, tmp, on_log):
        # ★★ 查询失败**必须抛出去**，绝不能当成"0 命中"。
        #    实测踩到：CodeQL 的 IMB 缓存目录被另一个进程锁住 → 退出码 2 →
        #    却记成"命中 0 条"，在基准上表现为**假漏检**（凭空压低召回率）。
        # 这是同一类"失败伪装成结论"的问题（参 的截断坑）。
        raise RuntimeError(f"CodeQL analysis failed ({project}): the query did not run, "
                           "which is not the same as no results")
    raw = parse_results(tmp, project)
    on_log(f"[parse] {len(raw)} raw result(s)")
    argsrc = run_and_parse_argsrc(db_dir, project, on_log)
    return finalize(raw, db_dir, filters, on_log, argsrc=argsrc, src_fallback=src_fallback)
