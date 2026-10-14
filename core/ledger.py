"""C2 · 目标台账记账（接进流水线）——「挖过 / 没挖过」分开记。

★ 为什么需要（`docs/169` B2 → `docs/184` §5 偏差 3）：
  `data/target_pool/target_ledger.json` 这个文件**存在、而且有数据**，
  但全仓 **没有任何 .py 读它或写它**（2026-10-12 grep 确认）→ 它是**死文件**。
  → 结果"这个靶挖过没挖过、用哪种形态挖的"**没法查** → 只能靠我记不记得 → 就会重复劳动。

★★ 本模块补三件事：
  1. **写**：一轮跑完，自动把该轮扫过的靶记进台账（轮次、计数、时间、形态）；
  2. ★ **记形态**：`forms` —— 从 `<round>/meta.json` 的 `sink_switches_effective` 取
     （这个字段 2026-10-12 才补上，之前的轮次记成 `unknown`，**不许倒推**）；
  3. **读**：`--show` / `--check <targets>` 回答"这些靶挖过没、用哪种形态挖的"
     —— 起新一轮之前先看它，避免重复劳动。

★ 计数口径：**从该靶历次轮次的 `findings.json` 取并集后去重**（按 fingerprint），
  不是把各轮的计数相加 —— 同一个洞会在多轮里重复出现，相加会虚高。
  覆盖已有文件前**一律先备份** `target_ledger.prev.json`。

用法：
    python core/ledger.py --round round-a1allforms      # 给一轮记账
    python core/ledger.py --show                        # 看台账全貌
    python core/ledger.py --check sampleservice,openjudge # 起新轮前查重
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "data" / "target_pool" / "target_ledger.json"
OUT = ROOT / "out"

# ★ 形态名（与 core/gen_ql.py 的 group 开关一一对应）
FORM_KEYS = [
    ("AF_SINKS_PATH", "path"),        # 路径构造
    ("AF_SINKS_HTTP", "http"),        # httpx/aiohttp
    ("AF_SINKS_FS", "fs"),            # 文件 I/O
    ("AF_DUALITY_SDK", "sdk"),        # SDK 构造
    ("AF_SINKS_DYNIMP", "dynimp"),     # 动态导入
]


def _load() -> dict:
    if LEDGER.exists():
        try:
            return json.loads(LEDGER.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"_meta": {}, "targets": {}}


def _save(d: dict) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    if LEDGER.exists():                      # ★ 覆盖前备份
        shutil.copy(LEDGER, LEDGER.with_name("target_ledger.prev.json"))
    d.setdefault("_meta", {})["updated_at"] = datetime.now().isoformat(timespec="seconds")
    LEDGER.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")


def forms_of_round(tag: str) -> list[str]:
    """从该轮 meta 的 `sink_switches_effective` 推出用了哪几种形态。

    ★★ 2026-10-12 修：这里原来直接拼 `OUT / tag` —— 而 `meta.json` 的 `tag` 字段是
      **不带 `round-` 前缀**的（`a1fix_static`），目录却是 `out/round-a1fix_static`
      → **找不到 meta → 静默退化成 `unknown`**。
      ★ 这就是"同一个病的**第 4 次**"：`out/<tag>` 与 `out/round-<tag>` 两套拼法混用
      （前三次见 `_recount` 的前缀漏读 / `arg_src` vs `arg_sources`）。
      → **结论：凡是用字符串拼路径/键的地方，都要走同一个规范化函数（这里 = `round_dir()`），只写一次。**
    ★ 老轮次没有该字段 → 返回 `['unknown']`，**不倒推**（宁可标未知，不许编）。
    """
    rd = round_dir(tag)
    if rd is None:
        return ["unknown"]
    try:
        m = json.loads((rd / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        return ["unknown"]
    sw = m.get("sink_switches_effective")
    if not isinstance(sw, dict):
        return ["unknown"]
    forms = [name for key, name in FORM_KEYS if sw.get(key) is True]
    if sw.get("AF_SINKS_EXTRA") is False:
        forms.append("baseline")            # 空 extra = 与论文原包一致的基线
    return forms or ["plain"]               # 全关 = 默认（显眼）形态


def round_dir(tag: str) -> Path | None:
    """★ 兼容两种存在形式：`out/<tag>` 与 `out/round-<tag>`。

    ★ 踩过的坑（2026-10-12 自己造成）：台账里的 `rounds` 是**带 `round-` 前缀**存的
      （`round-pathnose_nofs`），而 `meta.json` 的 `tag` 是**不带前缀**的（`a1allforms`）。
      不兼容的后果：`_recount` 去找 `out/a1allforms/findings.json`（不存在）
      → **静默把刚记进去的轮次漏掉** → 计数从 140 掉到 28，而且**一声不响**。
      → 所以这里两个都试，且**读不到必须能出声**（见 `_recount` 的 `missing`）。
    """
    for cand in (OUT / tag, OUT / f"round-{tag}"):
        if (cand / "findings.json").exists():
            return cand
    return None


def _recount(target: str, rounds: list[str]) -> dict:
    """把该靶历次轮次的 findings.json 取**并集去重**后计数（★ 不是相加）。

    ★ 读不到的轮次**逐个记下来**（`rounds_missing`），绝不许静默跳过 ——
      静默跳过会让"计数变小"看起来像"这个靶本来就没几条"。
    """
    seen: dict = {}
    missing: list[str] = []
    for tag in rounds:
        rd = round_dir(tag)
        if rd is None:
            missing.append(tag)
            continue
        try:
            d = json.loads((rd / "findings.json").read_text(encoding="utf-8"))
        except Exception:
            missing.append(tag)
            continue
        for fp, v in d.items():
            if v.get("project") == target:
                seen.setdefault(fp, v)
    c = Counter((v.get("ai_verdict") or "").strip() for v in seen.values())
    return {"n_candidates": len(seen),
            "vuln": c.get("vuln", 0),
            "needs_human": c.get("needs_human", 0),
            "not_vuln": c.get("not_vuln", 0),
            "unjudged": c.get("", 0),
            "rounds_read": len(rounds) - len(missing),
            "rounds_missing": missing}


def record_from_round(rd: Path, on_log=print) -> dict:
    """把一轮扫过的靶记进台账。返回被更新的靶名列表信息。"""
    rd = Path(rd)
    mf = rd / "meta.json"
    if not mf.exists():
        on_log(f"  [ledger] 找不到 {mf}，跳过")
        return {}
    meta = json.loads(mf.read_text(encoding="utf-8"))
    tag = meta.get("tag") or rd.name.replace("round-", "")
    per = meta.get("per_project") or {}
    if not per:
        on_log("  [ledger] meta 里没有 per_project，跳过")
        return {}

    forms = forms_of_round(tag)
    tag_key = tag if tag.startswith("round-") else f"round-{tag}"   # ★ 与已有 rounds 的写法对齐
    led = _load()
    led.setdefault("_meta", {}).setdefault("round_forms", {})[tag_key] = forms
    led["_meta"].setdefault("note",
        "forms 自 2026-10-12 起记录（早于此的轮次记 unknown，不倒推）。"
        "n_* 是历次轮次取并集去重后的计数，不是各轮相加；"
        "rounds_missing 列出**读不到 findings.json 的轮次**（静默跳过会让计数假性变小）。")
    touched, all_missing = [], []
    for name in per:
        t = led["targets"].setdefault(name, {})
        rounds = t.setdefault("rounds", [])
        if tag_key not in rounds:
            rounds.append(tag_key)
        cnt = _recount(name, rounds)
        ms = cnt.pop("rounds_missing")
        if ms:
            all_missing.append((name, ms))
        t.update(cnt)
        t["digged"] = True
        t["last_round"] = tag_key
        t["last_scan_at"] = meta.get("generated_at")
        t["forms"] = sorted({f for r in rounds
                             for f in led["_meta"]["round_forms"].get(r, ["unknown"])})
        touched.append(name)
    _save(led)
    on_log(f"  [ledger] 记账 {len(touched)} 个靶（形态 {forms}，轮次键 {tag_key}）→ {LEDGER.name}")
    for name, ms in all_missing:
        on_log(f"  [ledger] ★★ {name}: {len(ms)} 个轮次**读不到** findings.json → {ms}（不许当 0 用）")
    return {"tag": tag_key, "forms": forms, "targets": touched, "rounds_missing": all_missing}


def canon(tag: str) -> str:
    """把轮次名规范成 `out/` 下的**真实目录名**（能解析就解析，解析不了原样保留）。"""
    rd = round_dir(tag)
    return rd.name if rd else tag


def sync_from_out(on_log=print) -> dict:
    """★ 从 `out/round-*/findings.json` 反推「每个靶扫过哪些轮次」，补进台账。

    ★★ 为什么需要：2026-10-12 体检发现 —— `out/` 下 **93 个轮次有 findings.json**，
      而台账里只记了 **58 个**（35 个从未被记进任何靶）。
      → 台账**从来没记全过**，拿它当"挖过没挖过"的证据是**不可靠的**。
      修法不是"以后记得记"，而是让它变成 **`out/` 的物化索引**（文件系统才是 ground truth）：
      每次可以从头重建，永远能对齐。

    ★ 同时把 `rounds` 里的名字规范化（`a1allforms` → `round-a1allforms`），
      清掉历史遗留的**无前缀重复项**（那会让 `_recount` 静默读不到）。
    """
    led = _load()
    ts = led.setdefault("targets", {})
    added, canon_fixed = 0, []
    rounds_seen: set[str] = set()
    for rd in sorted(OUT.glob("round-*")):
        f = rd / "findings.json"
        if not f.exists():
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        rounds_seen.add(rd.name)
        projs = {v.get("project") for v in d.values() if v.get("project")}
        for p in projs:
            t = ts.setdefault(p, {})
            rs = t.setdefault("rounds", [])
            if rd.name not in rs:
                if p not in ts or not rs:
                    pass
                rs.append(rd.name)
                added += 1
    # 规范化 + 去重（清掉无前缀的重复项）
    for name, t in ts.items():
        old = list(t.get("rounds", []))
        norm = []
        for r in old:
            c = canon(r)
            if c not in norm:
                norm.append(c)
        if norm != old:
            canon_fixed.append((name, [x for x in old if x not in norm]))
        t["rounds"] = norm
    _save(led)
    on_log(f"  [ledger] 同步 out/ → 新增轮次记录 {added} 条；"
           f"规范化 {len(canon_fixed)} 个靶的轮次名（清掉无前缀重复项）")
    for n, dropped in canon_fixed[:6]:
        on_log(f"    {n:<22} 去掉 {dropped}")
    return {"added": added, "canon_fixed": canon_fixed}


def rebuild_all(on_log=print) -> dict:
    """★ 全量重算：把台账里**所有**靶按其 `rounds` 重算一遍。

    为什么要它：`record_from_round` 只碰"本轮扫过的靶"，于是**没被碰到的靶会保留旧口径**，
    台账里出现两套语义混着用（2026-10-12 修 `round-` 前缀 bug 时正是这个局面）。
    全量重算让**整张表口径一致**；旧表已备份为 `target_ledger.prev.json`。
    """
    led = _load()
    ts = led.get("targets", {})
    # ★★ 顺带**补算历史轮次的形态**：以前记成 `unknown` 的（含"根本没记过"的），
    #    只要该轮 meta.json 里有 `sink_switches_effective`，就补上真值。
    rf = led.setdefault("_meta", {}).setdefault("round_forms", {})
    all_rounds = sorted({r for t in ts.values() for r in t.get("rounds", [])})
    fixed_forms = 0
    for r in all_rounds:
        if rf.get(r) in (None, ["unknown"]):
            f = forms_of_round(r)
            if f != ["unknown"]:
                rf[r] = f
                fixed_forms += 1
    on_log(f"  [ledger] 形态补算：{fixed_forms}/{len(all_rounds)} 个轮次拿到了真实 forms")
    all_missing, chg = [], []
    for name, t in ts.items():
        rounds = t.get("rounds", [])
        if not rounds:
            continue
        old = t.get("n_candidates")
        cnt = _recount(name, rounds)
        ms = cnt.pop("rounds_missing")
        if ms:
            all_missing.append((name, ms))
        t.update(cnt)
        # ★★ 必须同步 `digged` —— 否则从 out/ 反推出来的靶会**有计数却报"没挖过"**，
        #    而那正是"避免重复劳动"这个用途上最危险的一种假阴性（2026-10-12 实测撞到：
        #    sfa/agentica/gta 有 17/69/86 条候选，`--check` 却说"没挖过"）。
        t["digged"] = bool(rounds)
        t["last_round"] = rounds[-1] if rounds else t.get("last_round")
        t["forms"] = sorted({f for r in rounds
                             for f in led.get("_meta", {}).get("round_forms", {}).get(r, ["unknown"])})
        if old != cnt["n_candidates"]:
            chg.append((name, old, cnt["n_candidates"]))
    led.setdefault("_meta", {})["counts_source"] = (
        "rebuilt 2026-10-12：按 rounds 逐轮读 findings.json 取并集去重（project==target），"
        "口径与 record_from_round 一致。旧表见 target_ledger.prev.json。")
    _save(led)
    on_log(f"  [ledger] 全量重算完成：{len(ts)} 个靶，其中 {len(chg)} 个计数变了")
    for n, o, x in chg[:20]:
        on_log(f"    {n:<24} {o} → {x}")
    if len(chg) > 20:
        on_log(f"    …另有 {len(chg)-20} 个")
    for name, ms in all_missing:
        on_log(f"  ★★ {name}: {len(ms)} 个轮次读不到 → {ms}")
    return {"changed": chg, "missing": all_missing}


def check(names: list[str], on_log=print) -> dict:
    """起新一轮之前查重：这些靶挖过没？用哪种形态挖的？"""
    led = _load()
    res = {}
    for n in names:
        t = led["targets"].get(n)
        if not t:
            res[n] = {"digged": False, "forms": [], "rounds": []}
        else:
            res[n] = {"digged": bool(t.get("digged")), "forms": t.get("forms", []),
                      "rounds": t.get("rounds", []), "vuln": t.get("vuln", 0),
                      "last_scan_at": t.get("last_scan_at")}
    for n, v in res.items():
        if not v["digged"]:
            on_log(f"  {n:<22} ✅ 没挖过")
        else:
            on_log(f"  {n:<22} ⚠️ 挖过（形态 {v['forms']}，{len(v['rounds'])} 轮，"
                  f"vuln={v.get('vuln', 0)}，最后 {str(v.get('last_scan_at'))[:10]}）")
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", default="")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--check", default="", help="逗号分隔的靶短名")
    ap.add_argument("--rebuild", action="store_true", help="★ 全量重算（统一口径）")
    ap.add_argument("--sync", action="store_true",
                    help="★ 从 out/ 反推轮次补进台账（把台账变成 out/ 的物化索引）")
    a = ap.parse_args()

    if a.sync:
        sync_from_out()
        return 0
    if a.rebuild:
        rebuild_all()
        return 0
    if a.round:
        rd = Path(a.round)
        if not rd.is_absolute():
            rd = OUT / a.round
        r = record_from_round(rd)
        return 0 if r else 2
    if a.check:
        check([x.strip() for x in a.check.split(",") if x.strip()])
        return 0
    if a.show:
        led = _load()
        ts = led.get("targets", {})
        dug = [k for k, v in ts.items() if v.get("digged")]
        print(f"台账靶数 {len(ts)} ｜ 挖过 {len(dug)}")
        for k, v in sorted(ts.items(), key=lambda x: -int(x[1].get("vuln") or 0)):
            if v.get("digged"):
                print(f"  {k:<24} rounds={len(v.get('rounds', [])):<3} "
                      f"n={v.get('n_candidates', 0):<5} vuln={v.get('vuln', 0):<3} "
                      f"forms={','.join(v.get('forms', []))}")
        rf = led.get("_meta", {}).get("round_forms", {})
        print(f"\n轮次形态表（{len(rf)} 条）:")
        for tag, f in list(rf.items())[:20]:
            print(f"  {tag:<28} {f}")
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
