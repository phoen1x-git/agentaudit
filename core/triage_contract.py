"""Validate model output and keep unsupported conclusions out of automatic triage.

References are checked against the exact displayed source, not a fresh read of disk.
A matching quotation proves provenance only; it does not prove the model's reasoning.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math

VERSION = "evidence-triage-v1"
ENUMS = {
    "ai_verdict": {"vuln", "not_vuln", "needs_human"},
    "by_design": {"yes", "no", "unclear"},
    "scope_exceeds": {"yes", "no", "unclear"},
    "guards_real": {"yes", "no", "unclear"},
    "arg_source": {"llm_output", "user_input", "tool_arg", "memory", "config", "constant", "unknown"},
    "source_trust": {"trusted", "untrusted", "unknown"},
    "sink_action": {"exec_code", "exec_sql", "http", "subprocess", "file", "other"},
}
TEXT_FIELDS = ("by_design_evidence", "scope_exceeds_evidence", "danger_arg",
               "arg_source_evidence", "source_trust_evidence", "guards_evidence", "one_line")
CLAIMS = ("source", "guard", "scope", "trust")


class ContractError(ValueError):
    """The response cannot be interpreted as a triage record."""


def digest(value) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate(response) -> dict:
    if not isinstance(response, dict):
        raise ContractError("response must be an object")
    for name, allowed in ENUMS.items():
        if not isinstance(response.get(name), str) or response[name] not in allowed:
            raise ContractError(f"invalid or missing {name}")
    conf = response.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        raise ContractError("confidence must be a number")
    if not 0 <= conf <= 1 or not math.isfinite(conf):
        raise ContractError("confidence must be finite and in [0, 1]")
    for name in TEXT_FIELDS:
        if not isinstance(response.get(name), str) or not response[name].strip():
            raise ContractError(f"invalid or missing {name}")
    gaps = response.get("missing_evidence")
    if not isinstance(gaps, list) or any(not isinstance(x, str) or not x.strip() for x in gaps):
        raise ContractError("missing_evidence must be a list of nonempty strings")
    evidence = response.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != set(CLAIMS):
        raise ContractError("evidence must contain source, guard, scope and trust lists")
    for claim, refs in evidence.items():
        if not isinstance(refs, list):
            raise ContractError(f"evidence.{claim} must be a list")
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) != {"file", "line", "quote"}:
                raise ContractError(f"invalid evidence.{claim} reference")
            if not isinstance(ref["file"], str) or not ref["file"]:
                raise ContractError("reference file must be nonempty")
            if type(ref["line"]) is not int or ref["line"] < 1:
                raise ContractError("reference line must be a positive integer")
            if not isinstance(ref["quote"], str) or not ref["quote"].strip():
                raise ContractError("reference quote must be nonempty")
    # Model-generated private keys must never impersonate our audit/provenance fields.
    if any(not isinstance(k, str) or k.startswith("_") for k in response):
        raise ContractError("private metadata keys are reserved")
    return copy.deepcopy(response)


def apply_policy(response, snapshot: dict | None = None) -> tuple[dict, list[str]]:
    """Return a checked copy. Never promote an uncertain response to safe or risky."""
    out = validate(response)
    snapshot = snapshot or {}
    rows = {(r["file"], r["line"]): r["text"].strip() for r in snapshot.get("lines", [])}
    matched = {}
    reasons = []
    for claim, refs in out["evidence"].items():
        matched[claim] = bool(refs) and all(
            rows.get((r["file"], r["line"])) == r["quote"].strip() for r in refs)
        if refs and not matched[claim]:
            reasons.append(f"{claim} 引用未匹配到所提供源码")
    reasons.extend(snapshot.get("blocking_gaps", []))
    reasons.extend(out["missing_evidence"])
    source_known = out["arg_source"] != "unknown" and out["source_trust"] != "unknown"
    if out["ai_verdict"] != "needs_human":
        if not source_known:
            reasons.append("实参来源或控制者仍未知")
        if not matched["source"]:
            reasons.append("缺少可定位的实参来源证据")
    if out["ai_verdict"] == "not_vuln":
        constant = out["arg_source"] == "constant" and out["source_trust"] == "trusted"
        config = (out["arg_source"] == "config" and out["source_trust"] == "trusted"
                  and matched["trust"])
        guard = out["guards_real"] == "yes" and matched["guard"]
        scope = (out["by_design"] == "yes" and out["scope_exceeds"] == "no"
                 and matched["scope"])
        if not (constant or config or guard or scope):
            reasons.append("没有带源码引用的常量、可信配置、有效防护或范围约束依据")
        if out["scope_exceeds"] == "yes":
            reasons.append("排除结论与超出范围的判断冲突")
    elif out["ai_verdict"] == "vuln":
        if out["source_trust"] != "untrusted":
            reasons.append("尚未说明危险实参由不可信主体控制")
        if out["arg_source"] == "config" and not matched["trust"]:
            reasons.append("配置控制者缺少源码引用")
        direct = out["by_design"] == "no" and out["guards_real"] == "no"
        exceeds = (out["by_design"] == "yes" and out["scope_exceeds"] == "yes"
                   and out["guards_real"] == "no" and matched["scope"])
        if not (direct or exceeds):
            reasons.append("风险结论与用途、范围或防护判断不一致")
    reasons = list(dict.fromkeys(reasons))
    if reasons and out["ai_verdict"] != "needs_human":
        out["ai_verdict"] = "needs_human"
        out["one_line"] = "[证据检查] " + "；".join(reasons) + " | " + out["one_line"]
    return out, reasons
