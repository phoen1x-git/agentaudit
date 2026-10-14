# -*- coding: utf-8 -*-
"""★★ 用**统一框架**跑旋钮三、旋钮四，让数字和基线可比。

★ 关键：判据是**同一个 prompt**（exp_framework.RUBRIC_UNIFIED），
  只是**候选来源不同**：
    baseline = 论文原三类出口
    knob3    = 旋钮三的扩展出口（+ 入口）
    knob4    = 旋钮四的扩展入口
"""
# ★★★ 不要在这里包 sys.stdout —— exp_framework 已经包过一次，
#   再包一层会把上一个 wrapper 关掉 → print() 抛
#   "I/O operation on closed file"。
#   ★ 这个坑和 docs/0.20 那三个「静默失败」是同一类：
#   两处都以为自己配好了，结果互相打架。
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import exp_framework as E
from collections import Counter

POOL = E.POOL


def load_json_list(fn):
    p = os.path.join(POOL, fn)
    if not os.path.exists(p):
        return []
    return json.load(open(p, encoding="utf-8"))


def to_evidence(items, cell):
    for it in items:
        ev = dict(it)
        ev["_cell"] = cell
        yield ev


def stratify_by(items, keyfn):
    """★ 按 keyfn 分层，而不是按固定 cell ——因为旋钮三/四的 cell 是单一值，
    按 cell 分层会退化成「每项目取 N 个」，样本量取决于项目数而不是类型数。
    """
    byrepo = {}
    for it in items:
        k = keyfn(it)
        byrepo.setdefault((it["_repo"], k), []).append(it)
    return byrepo


def run(name, items, per_stratum, keyfn=None):
    print()
    print("=" * 74)
    print("★ 实验 %s（统一口径）" % name)
    print("=" * 74)
    tot = len(items)
    # ★ 分层：默认按 cell；旋钮三按 cat、旋钮四按入口类型
    keyfn = keyfn or (lambda it: it.get("_cell", "?"))
    bystratum = stratify_by(items, keyfn)
    picked = []
    for (repo, k) in sorted(bystratum, key=lambda x: (x[0], x[1])):
        lst = sorted(bystratum[(repo, k)], key=lambda x: (x["file"], x["line"]))
        picked.extend(lst[:per_stratum])
    print("候选 %d 处 / %d 个(项目×层) → 分层抽样 %d 处"
          % (tot, len(bystratum), len(picked)))

    out = os.path.join(POOL, "exp_%s.json" % name)
    done = json.load(open(out, encoding="utf-8")) if os.path.exists(out) else {}
    verdicts = []
    cost0 = E.LC.USAGE.cny
    for i, ev in enumerate(picked, 1):
        key = "%s|%s|%d" % (ev["_repo"], ev["file"], ev["line"])
        if key in done:
            verdicts.append(done[key].get("verdict"))
            continue
        r = E.judge_one(ev, tag="exp_" + name)
        if r is None:
            # ★ 失败必须计数，不能静默跳过（今天第四次栽这个）
            print("  ★ 定位失败：%s:%d" % (ev["file"], ev["line"]))
            continue
        done[key] = r
        json.dump(done, open(out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        verdicts.append(r.get("verdict"))
        if i % 20 == 0:
            print("  [%d/%d] %s" % (i, len(picked), dict(Counter(verdicts))))

    n = len(verdicts)
    good = sum(1 for v in verdicts if v == "real")
    p, lo, hi = E.wilson(good, n)
    print()
    print("  判定 %d 处：%s" % (n, dict(Counter(verdicts))))
    print("  ★ 精确率 = %d/%d = **%.1f%%**（95%%区间 %.1f%%~%.1f%%）"
          % (good, n, p * 100, lo * 100, hi * 100))
    sev = Counter(r.get("severity") for r in done.values()
                  if r.get("verdict") == "real")
    print("  real 严重性：%s" % dict(sev))
    print("  花费 %.4f 元" % (E.LC.USAGE.cny - cost0))

    ex = {}
    if os.path.exists(E.EXPERIMENTS):
        ex = json.load(open(E.EXPERIMENTS, encoding="utf-8"))
    ex[name] = {"n_candidates": tot, "n_sampled": len(picked),
                "n_judged": n, "n_real": good,
                "precision": p, "ci_lo": lo, "ci_hi": hi,
                "verdicts": dict(Counter(verdicts)), "severity": dict(sev)}
    json.dump(ex, open(E.EXPERIMENTS, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    return ex[name]


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    ps = int(os.environ.get("PS", "2"))



    if which in ("crit9", "both"):
        c9 = load_json_list("criterion9_duality.json")
        items = []
        for h in c9:
            # ★ 取弱写法的**第一处**作为可疑点（它才是嫌疑）
            ln = (h.get("weak_at") or [h.get("start")])[0]
            items.append({"_repo": h["_repo"], "_branch": h.get("_branch", "main"),
                          "file": h["file"], "line": ln,
                          "route": h.get("func", ""),
                          "text": (h.get("weak_code") or [""])[0][:150],
                          "_cell": h.get("cat", "?")})
        run("crit9", items, ps, keyfn=lambda it: (it.get("_cell") or "?"))
    if which in ("knob3", "both"):
        k3 = load_json_list("knob3_sinks.json")
        run("knob3", list(to_evidence(k3, "extended_sink")), ps,
            keyfn=lambda it: (it.get("cat") or "?"))
    if which in ("knob4", "both"):
        k4 = load_json_list("knob4_entries.json")
        # 转成 evidence 形态
        items = []
        for h in k4:
            items.append({"_repo": h["_repo"], "_branch": h.get("_branch", "main"),
                          "file": h["file"], "line": h["line"],
                          "route": h.get("func", ""),
                          "text": h.get("sig", "")[:150],
                          "_cell": "extended_entry"})
        run("knob4", items, ps)
