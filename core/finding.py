"""内核 · Finding —— 一条候选记录的数据结构。

★ 一条 Finding = 静态前端找出来的「一个可疑调用点」。
   它**不是**"一个漏洞"，只是一条线索。判定不在这里做。

★ 指纹（docs/95 §十②）：洞的身份不能用行号（行号会漂）。
   指纹 = 项目 | 相对路径 | sink 函数名 | 调用行归一化后的内容哈希
   → 同一处代码在两轮之间能被认出；上游改动后行号变了、指纹不变。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


def _norm(s: str) -> str:
    """归一化代码片段：去多余空白，去掉行号相关的东西。"""
    s = re.sub(r"\s+", " ", s or "").strip()
    return s


def make_fingerprint(project: str, relpath: str, sink_func: str, snippet: str) -> str:
    raw = f"{project}|{relpath}|{sink_func}|{_norm(snippet)}"
    h = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
    return f"{relpath}:{h}"


@dataclass
class Finding:
    # ---- 身份 ----
    project: str                      # 目标项目名（从库路径推得）
    fingerprint: str = ""             # 稳定指纹（见上）

    # ---- 静态前端给的原始信息 ----
    rule: str = ""                    # py-qs/bb-l7 | py-qs/str-constraint | py-qs/caller
    sink_func: str = ""               # 例：requests.get / execute_code / eval
    sink_uri: str = ""                # 相对路径，例：playground/UI/app.py
    sink_line: int = 0
    sink_col: int = 0
    entry: str = ""                   # 入口函数名（调用链的第一跳）
    depth: int = 0                    # 调用链跳数
    guards: list = field(default_factory=list)   # 该调用点被哪些 if 测试守着  ["file#line", ...]

    # ---- 人要看的东西 ----
    snippet: str = ""                 # 调用点那一行源码（从缓存源码里读）
    chain: str = ""                   # 可读调用链

    # ---- 去重后 ----
    variants: int = 1                 # 同一处被几条调用链指到（depth 不同会重复）
    entries: str = ""                 # 所有入口函数名（逗号分隔）

    # ---- 内部：源码根（judge 取源码用，不入表）----
    src_root: str = ""

    # ---- 跨过程数据流给出的「实参来源」（开关 dataflow-argsource）----
    # [{"i":0,"kind":"param","src_file":"bigquery_vector.py","src_line":240,
    #   "src_text":"...","arg_text":"..."}]
    # ★ 它修的是判定层的不稳（docs/108）：判定层被问"实参从哪来"却没有数据，
    #   于是在「诚实写 unknown」和「猜一个」之间横跳。
    arg_sources: list = field(default_factory=list)

    def arg_src_summary(self, limit: int = 4) -> str:
        """给 tsv / 判定层用的一行摘要。例：`arg0:param(id@bigquery_vector.py:240); arg1:local`"""
        if not self.arg_sources:
            return ""
        parts = []
        for a in self.arg_sources[:limit]:
            k = a.get("kind", "?")
            if k == "local":
                parts.append(f"arg{a.get('i')}:local")
            else:
                st = (a.get("src_text") or "").replace("ControlFlowNode for ", "").strip()
                parts.append(f"arg{a.get('i')}:{k}({st}@{a.get('src_file')}:{a.get('src_line')})")
        return "; ".join(parts)

    # ---- LLM 判定层（★ AI 复核，不是人工核实）----
    ai_verdict: str = ""              # vuln / not_vuln / needs_human / error
    ai_confidence: float = 0.0
    by_design: str = ""               # yes/no/unclear —— 是不是项目本来的设计功能
    scope_exceeds: str = ""           # yes/no/unclear —— 设计功能是否超出预期范围
    arg_source: str = ""              # llm_output/user_input/tool_arg/memory/config/constant/unknown
    guards_real: str = ""             # yes/no/unclear
    ai_reason: str = ""               # 一句话
    judge_json: dict = field(default_factory=dict)   # 判定层原始 JSON（不入 tsv，落 verdicts.json）

    # ---- 人工列（默认空，由人填；机器不许预填）----
    verdict: str = ""                 # confirmed / rejected（默认空 = 未看）

    def to_row(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "project": self.project,
            "rule": self.rule,
            "sink": self.sink_func,
            "file": self.sink_uri,
            "line": self.sink_line,
            "entry": self.entry,
            "depth": self.depth,
            "guards": len(self.guards),
            "variants": self.variants,
            "entry": self.entry,
            "entries": self.entries,
            "snippet": _norm(self.snippet)[:160],
            "arg_src": self.arg_src_summary(),
            "ai_verdict": self.ai_verdict,
            "conf": round(self.ai_confidence, 2),
            "by_design": self.by_design,
            "scope_exceeds": self.scope_exceeds,
            "arg_source": self.arg_source,
            "guards_real": self.guards_real,
            "ai_reason": self.ai_reason,
            "chain": _norm(self.chain)[:300],
            "verdict": self.verdict,
        }


COLS = ["fingerprint", "project", "rule", "sink", "file", "line",
        "depth", "guards", "variants", "entry", "entries",
        "snippet", "arg_src", "ai_verdict", "conf", "by_design", "scope_exceeds",
        "arg_source", "guards_real", "ai_reason", "chain", "verdict"]


def dedup(findings: list["Finding"]) -> list["Finding"]:
    """开关 dedup-fingerprint：同一处代码只留一条。

    同一处调用点会被不同长度的调用链各指一次（depth=1/2/3…），指纹相同。
    代表取 depth 最小（链最短、最好解释）；guards 取并集；入口名汇总。
    """
    groups: dict[str, list[Finding]] = {}
    for fd in findings:
        groups.setdefault(fd.fingerprint, []).append(fd)
    out: list[Finding] = []
    for _fp, g in groups.items():
        g.sort(key=lambda x: (x.depth == 0, x.depth))
        rep = g[0]
        rep.variants = len(g)
        ents: list[str] = []
        for x in g:
            if x.entry and x.entry not in ents:
                ents.append(x.entry)
        rep.entries = ", ".join(ents[:6])
        gg: list[str] = []
        for x in g:
            for y in x.guards:
                if y not in gg:
                    gg.append(y)
        rep.guards = gg
        out.append(rep)
    out.sort(key=lambda x: (x.project, x.sink_uri, x.sink_line))
    return out
