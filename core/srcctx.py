"""内核 · 取源码上下文。

★ 判定层要读的是【真实的源码】，不是静态前端打印出来的摘要。
★ 定位函数一律用 AST，**不靠行号猜**（这条是踩过的：外部给的行号永远不能直接用）。
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def enclosing_function(path: str, line: int, max_lines: int = 120) -> tuple[str, str]:
    """返回 (函数限定名, 源码)。找不到返回 ("", "")。"""
    src = read_text(path)
    if not src or not line:
        return "", ""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return "", ""
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lo = node.lineno
            hi = getattr(node, "end_lineno", lo) or lo
            if lo <= line <= hi:
                # 取最内层（区间最小的）
                if best is None or (hi - lo) < (best[2] - best[1]):
                    best = (node, lo, hi)
    if best is None:
        return "", ""
    node, lo, hi = best
    _all = src.splitlines()[lo - 1:hi]
    if len(_all) > max_lines:
        # ★★★ 修—— **不再从头截**。
        #   旧行为：`body[:max_lines]` = 只看函数的**前 N 行**，后面的**全丢**。
        #   ★ 后果：9 条结论翻转里**有 1 条**的理由原文就是
        #     「给定函数源码被截断、看不到 o…」—— 而**危险调用恰恰常在函数末尾**。
        #   新行为：**保证「目标行」一定落在窗口里** ——
        #     以它为锚，前面留够（含函数签名，用于看参数怎么来的），后面留够（含危险调用后的收尾）。
        #   ★ 并且**明确标注两端各丢了多少行**（不再只写一句"截断"，让判定层知道缺的是什么）。
        _idx = max(0, min(line - lo, len(_all) - 1))      # 目标行在函数体内的下标
        _head = min(8, _idx)                              # 函数签名 + 开头几行（看参数来源）
        _start = max(0, _idx - max(_head, int(max_lines * 0.45)))
        _end = min(len(_all), _start + max_lines)
        _start = max(0, _end - max_lines)                 # 若已经到底，往前补满窗口
        _marks = []
        if _start > 0:
            _marks.append(f"前面还有 {_start} 行未显示")
        if _end < len(_all):
            _marks.append(f"后面还有 {len(_all) - _end} 行未显示")
        body = "\n".join(_all[_start:_end])
        body += ("\n    # ...（★ 本段是**窗口**，不是全文：%s；"
                 "★ **目标行就在本段内**，请只依据本段判断）" % "；".join(_marks))
    else:
        body = "\n".join(_all)
    return _qualname(node), body


def function_named(path: str, name: str, max_lines: int = 90) -> str:
    """按【函数名】找函数源码（模型调用链里给的是名字，不是行号）。

    支持 'Class.method' / 'module.func'；用末段名字匹配，命中最内层同名者。
    """
    src = read_text(path)
    if not src:
        return ""
    short = name.split(".")[-1].strip()
    if not short:
        return ""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return ""
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == short:
            lo = node.lineno
            hi = getattr(node, "end_lineno", lo) or lo
            hits.append((hi - lo, lo, hi))
    if not hits:
        return ""
    _sz, lo, hi = min(hits)
    body = "\n".join(src.splitlines()[lo - 1:hi])
    lines = body.splitlines()
    if len(lines) > max_lines:
        body = "\n".join(lines[:max_lines]) + "\n    # ...（截断）"
    return body


def lines_at(path: str, linenos: list[int], width: int = 2) -> list[str]:
    """取若干行（带行号），给"路径上的 if 守卫"用。"""
    src = read_text(path).splitlines()
    out = []
    for ln in linenos:
        if 1 <= ln <= len(src):
            out.append(f"{ln}: {src[ln - 1].strip()}")
    return out


_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache"}
_PY_INDEX: dict[str, list[str]] = {}
_INDEX_ROOT: str | None = None


def index_py(root: str) -> dict[str, list[str]]:
    """建/取「文件名(小写) → [完整路径]」索引（走一次磁盘，之后复用）。

    ★ 为什么需要：跨过程数据流给出的源头位置只有**文件名**（如 `schema_constants.py`），
      而那个文件通常**不在 sink 所在目录** —— 必须在整棵源码树里找。
    """
    global _INDEX_ROOT
    if _INDEX_ROOT != root or not _PY_INDEX:
        idx: dict[str, list[str]] = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fn in filenames:
                if fn.endswith(".py"):
                    idx.setdefault(fn.lower(), []).append(os.path.join(dirpath, fn))
        _PY_INDEX.clear()
        _PY_INDEX.update(idx)
        _INDEX_ROOT = root
    return _PY_INDEX


def function_by_basename(root: str, basename: str, line: int,
                         prefer_dir: str = "", max_lines: int = 70) -> tuple[str, str, str]:
    """按【文件名 + 行号】找函数。返回 (限定名, 源码, 完整路径)。

    ★ 用途：数据流说"实参可追溯到 param `catalog` @ schema_constants.py:90"，
      第 90 行就是那个函数**接收这个值**的地方 —— 校验（白名单/正则）往往就在它体内。
      sink 所在函数看不到它，所以判定层之前只能答"依据在给定代码之外"。
    ★ 重名时优先与 sink 同目录的那一个（更可能是同一个模块）。
    """
    cands = index_py(root).get((basename or "").lower(), []) if root else []
    if not cands:
        return "", "", ""
    if prefer_dir:
        same = [p for p in cands if os.path.dirname(p) == prefer_dir]
        if same:
            cands = same
    for p in cands:
        q, body = enclosing_function(p, line, max_lines=max_lines)
        if body:
            return q, body, p
    return "", "", ""


def _qualname(node: ast.AST) -> str:
    """还原 Class.method（只回溯一层父级，够用）。"""
    return getattr(node, "name", "?")


# ---------------------------------------------------------------------------
# ★★ 「这个配置值是从哪一层来的」—— 补输入，不是加规则
# ---------------------------------------------------------------------------
#   背景：upstream issue（外部真值）里 `base_url = config.get("base_url")`，
#         判定层判不出它是"操作者自己配的"还是"随仓库 clone 下来的" ——
#         两种情况**可信度正好相反**，而判定层**看不到配置合并逻辑**。
#   ★ 做法：去**同一个仓库里**找"配置从哪来"的**原文**（不猜、不下结论），
#     把命中的**文件行原文**贴进 user prompt，让判定层自己判。
#   ★ 只贴证据、绝不替它下结论 —— 判定尺度仍在 rubric 里。

# 「配置分层 / 合并 / 覆盖」的代码痕迹
_RE_CFG_MERGE = re.compile(
    r"deep_?merge|_merge_?config|merge_?config|precedence|layered_config|"
    r"config_layers?|local_config|project_config|target_dir",
    re.I,
)

# 「项目内配置文件」被加载的写法：open(...'.sampleproj.json') / Path(dir) / '.mcp.json'
_RE_CFG_LOAD = re.compile(
    r"\.sampleproj\.json|\.mcp\.json|local_config_file|config_file.*target|"
    r"target_dir.*config|project_dir.*config",
    re.I,
)


def config_source_evidence(root: str, sink_path: str, limit: int = 8) -> list[dict]:
    """在源码树里找「配置来源分层」的原文证据。

    返回 [{"file": 相对路径, "line": 行号, "text": 该行原文, "why": 命中原因}]。

    ★ 只找两类东西（都是**可核的原文**）：
      ① 有代码在**加载"随仓库交付的配置文件"**（.sampleproj.json / .mcp.json / …）；
      ② 有代码在**做配置分层/合并/覆盖**（deep_merge / precedence / local_config / target_dir …）。
    ★ 特意**优先取与 sink 同目录或同仓根**的那些，避免跨包噪声。
    """
    if not root or not os.path.isdir(root):
        return []
    hits: list[dict] = []
    sink_dir = os.path.dirname(sink_path or "")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                txt = read_text(p)
            except Exception:
                continue
            if not txt:
                continue
            rel = os.path.relpath(p, root).replace("\\", "/")
            for i, line in enumerate(txt.splitlines(), 1):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                why = ""
                if _RE_CFG_LOAD.search(s):
                    why = "加载项目内配置文件"
                elif _RE_CFG_MERGE.search(s):
                    why = "配置分层/合并/覆盖"
                if not why:
                    continue
                # 文件里同时出现「项目内配置名」的和「分层」的更值得看
                hits.append({"file": rel, "line": i, "text": s[:180], "why": why,
                             "near": rel.startswith(sink_dir) if sink_dir else False})
    # 同目录的排前面；其余按文件名稳定排序（保证可复现）
    hits.sort(key=lambda h: (not h["near"], h["file"], h["line"]))
    return hits[:limit]

