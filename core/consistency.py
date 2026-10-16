"""内核 · 判定一致性检查（开关 consistency-check）

为什么要有它
------------
LLM 判定层最后那两层是**主观判断**：
  · `by_design`     这是不是项目本来就该做的事
  · `scope_exceeds` 它超出了预期范围没有
已实测到它会飘：同一项目、同一 sink、同一来源的两处 `exec`，
一个判 "not_vuln（既定行为）"、一个判 "vuln（超出范围）" —— **差异不来自代码，来自判定层自己的措辞**。
而这种飘动**直接改变最终 vuln 计数**。

★ 本模块只做一件事：**发现并报出来**，不改任何判定。
  为什么不自作主张改：改判定 = 又是一个单变量实验，得单独做、单独量。
  自查规则："结论对 ≠ 机制对"——先把它变成可看见的，再决定怎么修。

分组键为什么是 (project, sink, arg_source)
----------------------------------------
要找的是"**代码形态相同 → 结论却不同**"。
最接近"代码形态"的两个字段就是：调用了哪个函数（sink）、实参从哪来（arg_source）。

★ 为什么必须带上 `project`：不同项目的同名 sink 代码本来就长得不一样，
  跨项目比会大量误报（实测：`requests.get`+unknown 那组横跨 3 个项目，代码根本不同）。
  误报的代价是**人的时间**——正是这一环要省的东西。
  所以只在**同一项目内**比形态。

`by_design` / `scope_exceeds` 恰恰是**待测的主观输出**，所以不能拿它们分组
（拿它们分组会把不一致藏起来）。
"""
from __future__ import annotations

from collections import defaultdict


def shape_key(f) -> tuple:
    return (getattr(f, "project", "") or "",
            getattr(f, "sink_func", "") or "",
            getattr(f, "arg_source", "") or "")


def check(findings, min_group: int = 2) -> dict:
    """返回：
      · strict  —— 五个字段全同、但 ai_verdict 不同（理论上必须是 0；不为 0 说明判定层自相矛盾）
      · drift   —— 同 (sink, arg_source)，主观层出现多值（★ 主要产出）
      · stats   —— 分组数等
    """
    strict: dict[tuple, list] = defaultdict(list)
    shape: dict[tuple, list] = defaultdict(list)

    for f in findings:
        if not getattr(f, "ai_verdict", ""):
            continue                      # 没判定的（--no-llm）不参与
        full = (shape_key(f) + (f.guards_real, f.by_design, f.scope_exceeds))
        strict[full].append(f)
        shape[shape_key(f)].append(f)

    strict_bad = []
    for k, v in strict.items():
        if len({x.ai_verdict for x in v}) > 1:
            strict_bad.append({"key": k, "members": v})

    drift, drift_minor = [], []
    for k, v in shape.items():
        if len(v) < min_group:
            continue
        verdict_differs = len({x.ai_verdict for x in v}) > 1
        reason_differs = any(len({getattr(x, fld) for x in v}) > 1
                             for fld in ("by_design", "scope_exceeds"))
        if verdict_differs:
            drift.append({"key": k, "members": v})
        elif reason_differs:
            # 结论一致、但"设计功能/超出范围"这两个理由字段不一致 → 信息性，不是 bug
            drift_minor.append({"key": k, "members": v})

    # 严重度排序：组越大越靠前
    drift.sort(key=lambda d: -len(d["members"]))
    drift_minor.sort(key=lambda d: -len(d["members"]))
    return {
        "strict": strict_bad,
        "drift": drift,
        "drift_minor": drift_minor,
        "stats": {
            "n_judged": sum(len(v) for v in strict.values()),
            "n_shape_groups": len(shape),
            "n_strict_groups": len(strict),
            "n_strict_inconsistent": len(strict_bad),
            "n_drift_groups": len(drift),
            "n_drift_minor_groups": len(drift_minor),
        },
    }


def render_md(res: dict) -> str:
    s = res["stats"]
    L = ["# 判定一致性检查", ""]
    L += ["> ★ 只报不改。改判定要单独做单变量实验。", ""]
    L += ["## 统计", "",
          f"- 参与条数（已判定的）：**{s['n_judged']}**",
          f"- 形态组数 `(project, sink, arg_source)`：**{s['n_shape_groups']}**",
          f"- 同输入不同结论（严格约定，理论上必须 0）：**{s['n_strict_inconsistent']}**"
          f" / {s['n_strict_groups']} 组"] + (
          ["  - ★ 不为 0 → 判定层对完全相同的输入给出了不同结论，是硬 bug"] if s["n_strict_inconsistent"] else
          ["  - ✅ 为 0 → 给定它自己的字段，判定层内部自洽", ""]) + [
          f"- **同形态、结论不同（要人看）：{s['n_drift_groups']} 组**",
          f"- 同形态、结论一致但理由字段不同（信息性）：{s.get('n_drift_minor_groups', 0)} 组", ""]

    if not res["strict"] and not res["drift"]:
        L += ["## 结论", "", "未发现「同形态不同结论」。", ""]
        if res.get("drift_minor"):
            L += [f"（另有 {len(res['drift_minor'])} 组结论一致但 by_design/scope_exceeds 不同，"
                  "不影响结论，仅作观察。）", ""]
        return "\n".join(L)

    if res["drift"]:
        L += ["## ★ 同形态、结论不同（要人看）", ""]
        for i, d in enumerate(res["drift"], 1):
            proj, sink, src = d["key"]
            vs = " / ".join(sorted({x.ai_verdict for x in d["members"]}))
            L += [f"### {i}. `{proj}` · `{sink}` 实参来自 `{src}` —— 结论 {vs}"
                  f"（{len(d['members'])} 条）", ""]
            for x in d["members"]:
                L += [f"- **{x.ai_verdict}** · `by_design={x.by_design}` · "
                      f"`scope_exceeds={x.scope_exceeds}`"
                      f"  \n  `{x.project}` {x.sink_uri}:{x.sink_line}",
                      f"  \n  > {x.ai_reason}"]
            L += [""]
        L += ["★ 判读提示：先看**代码是不是真的同形态**（把上面几条的源码对一遍）。",
              "  如果代码确实一样而结论不同 → 是判定层在飘；如果代码不同 → 说明形态键不够细，要加维度。", ""]

    if res["strict"]:
        L += ["## ⚠ 同输入不同结论（硬 bug）", ""]
        for d in res["strict"]:
            L += [f"- key={d['key']}"]
            for x in d["members"]:
                L += [f"  - {x.ai_verdict}  {x.project} {x.sink_uri}:{x.sink_line}"]
        L += [""]

    if res.get("drift_minor"):
        L += ["## 附：结论一致、但理由字段不同（信息性）", ""]
        for d in res["drift_minor"]:
            proj, sink, src = d["key"]
            bd = "/".join(sorted({x.by_design for x in d["members"]}))
            ex = "/".join(sorted({x.scope_exceeds for x in d["members"]}))
            L += [f"- `{proj}` · `{sink}` (src={src}) —— 结论都是 "
                  f"{d['members'][0].ai_verdict}，但 by_design={bd}、scope_exceeds={ex}"]
        L += [""]

    return "\n".join(L)


def write_report(path, res: dict) -> None:
    path.write_text(render_md(res), encoding="utf-8")


# --------------------------------- Optional fix-up A: unknown-source downgrade
# ★ 依据（重复运行实测）：把一批"补了调用方上下文"的条目换缓存标签复判三轮，
#   从 `needs_human` 翻成 `vuln` 的 8 条里**三轮全稳只有 4/8** ——
#   而**不稳的几乎全是 `arg_source=unknown` 那一档**。
#
# ★ 为什么是"降级"而不是"按 vuln 处理"：
#   `unknown` 的字面含义是「**判定层看不到这个值从哪来**」。
#   既然看不到来源，就**不能断言"外部可控"** —— 正确答案是「待定，给人看」，
#   而不是替它猜一个。（同 `apply_downgrade`：不编我们并不掌握的结论。）
#
# ★ 为什么不是降成 `not_vuln`：我们**没有**证据说"它不是洞"，
#   只有证据说"**判得稳不稳**"。降成 `not_vuln` 会把可能真存在的洞埋掉。
#
# ★ Only the reporting verdict (`ai_verdict`) changes; the original one stays in
#   `ai_reason` and `verdicts.json`, so nothing is lost.
UNKNOWN_TOKENS = ("", "unknown", "none", "null", "n/a", "unknown_source")


def _is_unknown_source(x) -> bool:
    return (getattr(x, "arg_source", "") or "").strip().lower() in UNKNOWN_TOKENS


def apply_unknown_downgrade(findings, *, only_verdict: str = "vuln") -> list[dict]:
    """把「判 `vuln` 但实参来源未知」的条目降级为 `needs_human`。**幂等。**

    返回改动清单（`from` / `to` / `reason`），供日志使用。
    """
    changed: list[dict] = []
    for x in findings or []:
        if getattr(x, "ai_verdict", "") != only_verdict:
            continue
        if not _is_unknown_source(x):
            continue
        raw = (getattr(x, "arg_source", "") or "").strip()
        changed.append({"project": x.project, "file": x.sink_uri, "line": x.sink_line,
                        "sink": x.sink_func, "from": x.ai_verdict, "to": "needs_human",
                        "reason": "argument source unknown (unknown-downgrade)"})
        x.ai_verdict = "needs_human"
        x.ai_reason = ("[unknown-source downgrade] arg_source was "
                       f"`{raw or '(empty)'}`, i.e. the triage stage could not see where "
                       "this value comes from. Repeats of this bucket are only stable about "
                       "one time in three, so it must not be reported as-is. "
                       "Original reason: " + (x.ai_reason or "")[:120])
    return changed


# ---------------------------------------------------------------- 可选处置
def apply_downgrade(findings, res: dict) -> list[dict]:
    """把「同形态、结论不同」的组**整组降级为 needs_human**。

    ★ 为什么不是"统一成多数票"：
      多数票是在**编**一个我们并不掌握的结论。降级才是诚实的——
      判定层自己都对同形态代码给不出稳定答案，那正确答案就是"待定，给人看"。
    ★ 为什么默认不开：它会改判定 = 又一个单变量实验，要单独量。
      注意它是**保守方向**：只会让更少的东西被报出去。
    """
    changed = []
    for d in res["drift"]:
        for x in d["members"]:
            if x.ai_verdict != "needs_human":
                changed.append({"project": x.project, "file": x.sink_uri,
                                "line": x.sink_line, "sink": x.sink_func,
                                "from": x.ai_verdict, "to": "needs_human",
                                "reason": "同形态组内结论不一致（consistency-downgrade）"})
                x.ai_verdict = "needs_human"
                x.ai_reason = ("[一致性降级] 同项目中存在代码形态相同但结论不同的条目"
                               f"（本组 {len(d['members'])} 条），无法据此稳定判定。"
                               "原判定：" + (x.ai_reason or "")[:120])
    return changed
