"""A1 自用版入口 · 跑一轮。

    python app/run_round.py --tag 20261009

只做一件事：把「已建好的 CodeQL 库」批量变成 out/round-<tag>/ 下的
findings.tsv + scan.log + meta.json。

★ A1 = 全开跑最快（docs/96）。这一版只接静态前端，LLM 判定层下一轮。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # 个人项目_全自动挖掘
sys.path.insert(0, str(ROOT))

from core import static_frontend as SF                  # noqa: E402
from core import finding as F                           # noqa: E402
from core import gate as G                              # noqa: E402
from core import round as R                             # noqa: E402

WORKSPACE = ROOT.parent


def load_targets(path: str | None = None) -> dict:
    """读目标表（★ 不再是硬编码）。默认 core/config/targets.yml，可用 --targets-file 换。"""
    import yaml
    p = Path(path) if path else (ROOT / "core" / "config" / "targets.yml")
    if not p.is_absolute():
        p = ROOT / p
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    out = {}
    for name, t in (cfg.get("targets") or {}).items():
        out[name] = {
            "repo": t.get("repo"),
            "db": (ROOT / t["db"]).resolve() if t.get("db") else None,
            "src": (ROOT / t["src"]).resolve() if t.get("src") else None,
        }
    return out


TARGETS = load_targets()


def _cfg_stamp() -> dict:
    """内核版本戳：规则集 + 两个外置配置的内容哈希（照 criteria_ver.py 的做法）。"""
    out = {"rules": SF.QUERIES}
    for name in ("sinks.yml", "filters.yml", "static_frontend.py", "finding.py",
                 "cfg.py", "llm_judge.py", "consistency.py", "duality.py"):
        p = (ROOT / "core" / "config" / name) if name.endswith(".yml") else (ROOT / "core" / name)
        if p.exists():
            out[name] = hashlib.sha1(p.read_bytes()).hexdigest()[:12]
    # ★ 判定判据（rubric）单独打戳：改一句提示词会翻转判定结果，必须能追溯用的是哪一版
    try:
        from core import llm_judge as _LJ
        out["rubric"] = hashlib.sha1(_LJ.RUBRIC.encode("utf-8")).hexdigest()[:12]
    except Exception:
        pass
    return out


def _cost_since(since: str) -> tuple[int, float]:
    """★ 从用量日志算这一轮的真实花费。

    为什么不能直接用进程内的计数器：命中缓存的那一轮进程内是 0，
    但那一轮实际上"用掉"了之前花的钱 —— 报 0 会让论文的成本数字失真。
    """
    p = ROOT / "data" / "llm_usage.jsonl"
    n, c = 0, 0.0
    if not p.exists():
        return 0, 0.0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("tag") == "kernel_judge" and str(d.get("ts", "")) >= since:
            n += 1
            c += float(d.get("cny") or 0.0)
    return n, round(c, 4)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=datetime.now().strftime("%Y%m%d"))
    ap.add_argument("--only", default="", help="逗号分隔，只跑其中几个项目")
    ap.add_argument("--targets-file", default="", help="目标表 yml（默认 core/config/targets.yml）")
    ap.add_argument("--out", default=str(ROOT / "out"))
    ap.add_argument("--no-llm", action="store_true",
                    help="关掉 LLM 判定层（开关 llm-judge）；A1 默认打开")
    ap.add_argument("--judge-votes", type=int, default=1,
                    help="★ 每条判定重复跑 N 次再取多数票（默认 1）。"
                         "实测单次跑的结论不可复现（docs/108）；N>1 成本 ×N")
    ap.add_argument("--no-gate", action="store_true",
                    help="关掉目标健康门（归档/长期无人维护即跳过）；A1 默认打开")
    ap.add_argument("--gate-mode", default="", choices=["", "alive", "detect"],
                    help="★ 门的用途：alive=报给开发者（归档即跳过，默认）；"
                         "detect=验证检出能力（归档不跳，只要里面有真洞）。见 docs/113 §八")
    ap.add_argument("--no-consistency", action="store_true",
                    help="关掉判定一致性检查（只报不改）；A1 默认打开")
    ap.add_argument("--no-duality", action="store_true",
                    help="★ 关掉第 9 条判据 duality（同函数内强弱写法并存，候选生成器）。"
                         "它由 core/duality.py 从源码目录扫，与 CodeQL 前端并列；默认打开（docs/134 §四①）")
    ap.add_argument("--no-dataflow", action="store_true",
                    help="关掉跨过程实参来源（开关 dataflow-argsource）；"
                         "关掉后判定层看不到数据流证据，会退回 docs/108 的行为")
    ap.add_argument("--consistency-downgrade", action="store_true",
                    help="★ 可选处置：把同形态结论不一致的组整组降级为 needs_human"
                         "（保守方向；默认关，因为会改判定 = 单变量实验）")
    ap.add_argument("--no-upstream", action="store_true",
                    help="★ C1：关掉轮末的**候选级上游核查**（默认开）。只查 vuln 候选，"
                         "只写 upstream.json 当证据，**不改判定**。见 docs/184 §5 偏差 3")
    ap.add_argument("--no-ledger", action="store_true",
                    help="★ C2：关掉轮末的**目标台账记账**（默认开）。记「挖过没挖过 + 用哪种形态」")
    ap.add_argument("--no-cand-ledger", action="store_true",
                    help="★ 关掉轮末的**候选台账记账**（默认开）。记「每条候选我看到哪一步了」，"
                         "只追加事件、幂等。见 core/candidate_ledger.py")
    args = ap.parse_args()

    # ★ 开关 dataflow-argsource：前端在 import 期就会读这个环境变量，所以要在跑之前设。
    os.environ["AF_NO_DATAFLOW"] = "1" if args.no_dataflow else "0"

    # ★★ 生成 CodeQL 前端的 QL（core/ql/）。**必须每次跑都生成**：
    #    它按 core/config/sinks.yml + 当前环境变量决定 sink 集合（group 开关 AF_SINKS_*）。
    #    踩过的坑：手动改 sinks.yml 却没重生成 → run_round 用的是**旧 QL**，
    #    于是"开了开关却 0 变化"，白跑一轮还误判成"该 sink 无效果"。
    try:
        import subprocess as _sp
        _r = _sp.run([sys.executable, str(ROOT / "core" / "gen_ql.py")],
                     capture_output=True, text=True, encoding="utf-8", errors="replace")
        _gen_ok = _r.returncode == 0
        _gen_msg = (_r.stdout or "").strip().splitlines()[-1] if (_r.stdout or "").strip() else ""
    except Exception as _e:      # noqa: BLE001
        _gen_ok, _gen_msg = False, f"{type(_e).__name__}: {_e}"

    global TARGETS
    if args.targets_file:
        TARGETS = load_targets(args.targets_file)
    want = [s.strip() for s in args.only.split(",") if s.strip()] or list(TARGETS)
    rd = R.new_round_dir(Path(args.out), args.tag)
    t0 = time.time()
    started = datetime.fromtimestamp(t0).strftime("%Y-%m-%d %H:%M:%S")

    all_findings = []
    per_project = {}
    llm_cost = 0.0
    llm_calls = 0
    llm_cache_hits = 0
    with R.ScanLog(rd / "scan.log") as lg:
        lg.log(f"round dir = {rd}")
        lg.log(f"kernel stamp = {_cfg_stamp()}")
        lg.log(f"[gen_ql] ok={_gen_ok} | {_gen_msg}")
        # ★★ 形态开关快照（2026-10-12 补全）：以前只打 EXTRA/FS/HTTP 三个，
        #   ★ **漏打 PATH 与 SDK** → 事后无法从 scan.log 反推"这轮用了哪几种形态"
        #   （`core/ledger.py::forms_of_round` 只能读 meta 新字段，legacy 轮次全成 unknown）。
        #   现在遍历所有形态开关一次性打出 —— 以后加新开关也自动覆盖。
        #   ★ 注意 `AF_PATH_FILTER` 的默认值是字符串 `"rel"`（不是 0/1）——
        #     写日志时不能把默认当 '0'，否则会显示成"回到论文黑名单"而误导
        #     （2026-10-12 自查发现：gt1 的日志曾把 rel 打成 0）。
        _sw_defaults = {"AF_SINKS_EXTRA": "1", "AF_PATH_FILTER": "rel"}
        lg.log("[sinks] " + " ".join(
            f"{k}={os.environ.get(k, _sw_defaults.get(k, '0'))}"
            for k in ("AF_SINKS_EXTRA", "AF_SINKS_PATH", "AF_SINKS_HTTP", "AF_SINKS_FS",
                      "AF_SINKS_DYNIMP", "AF_DUALITY_SDK", "AF_PATH_FILTER")))
        for name in want:
            t = TARGETS.get(name)
            if t is None:
                lg.log(f"[SKIP] 未知项目 {name}")
                continue
            # ★★ 目标健康门：归档 / 长期无人维护 / fork / 停用 → 不扫（并说清为什么）
            if not args.no_gate and t.get("repo"):
                g = G.check(t["repo"], mode=(args.gate_mode or None))
                lg.log(f"[gate] {name} ({t['repo']}) → {G.summary(g)}")
                if g["verdict"] == "SKIP":
                    per_project[name] = {"status": "gated-out", "n": 0, "reasons": g["reasons"]}
                    continue
                if g["verdict"] == "UNKNOWN":
                    lg.log("       ★ 健康状态未知 → 仍然继续（不静默跳过）")
            db = t.get("db")
            if not db or not (db / "codeql-database.yml").exists():
                lg.log(f"[SKIP] {name}: 库不存在或未建好 → {db}")
                per_project[name] = {"status": "no-db", "n": 0}
                continue
            lg.log(f"--- {name} : {db}")
            try:
                fnd = SF.run_db_to_findings(str(db), name, on_log=lg.log)
            except Exception as e:            # 失败要出声，不静默
                lg.log(f"[FAIL] {name} 异常: {type(e).__name__}: {e}")
                per_project[name] = {"status": "error", "n": 0}
                continue
            n_sf = len(fnd)
            # ---- ★ 第 9 条判据（duality）：同函数内强弱并存 → 候选生成器（docs/134 §四①）----
            #      它从源码目录扫，与 CodeQL 前端并列；已过「常量/净化」过滤（core/duality.py）
            n_du = 0
            if not args.no_duality and t.get("src"):
                try:
                    from core import duality as DX
                    dx = DX.scan_dir(t["src"], name, on_log=lg.log)
                    n_du = len(dx)
                    fnd = list(fnd) + list(dx)
                except Exception as e:
                    lg.log(f"[duality][FAIL] {name}: {type(e).__name__}: {e}")
            elif not args.no_duality:
                lg.log(f"[duality] {name}: 目标表没有 src → 跳过（只跑了 CodeQL 前端）")
            if not fnd:
                lg.log(f"[WARN] {name} 命中 0 条 —— 可能是真没有，也可能是判据没覆盖，要单独核")
            before = len(fnd)
            fnd = F.dedup(fnd)                      # 开关 dedup-fingerprint
            lg.log(f"[dedup] {name}: {before} → {len(fnd)} 条（同指纹合并）")
            per_project[name] = {"status": "ok", "n": len(fnd), "n_raw": before,
                                 "n_static_frontend": n_sf, "n_duality": n_du}
            all_findings.extend(fnd)

        # ---- LLM 判定层（开关 llm-judge）----
        if not args.no_llm and all_findings:
            from core import llm_judge as LJ
            _v = max(1, args.judge_votes)
            lg.log(f"[judge] LLM 判定 {len(all_findings)} 条（AI 复核，非人工）"
                   + (f"｜每条重复 {_v} 次取多数票" if _v > 1 else "｜单次"))
            if _v > 1:
                lg.log(f"[judge] ★ N>1：成本 ×{_v}，且每次用不同 tag 绕缓存"
                       "（不绕则 N 次返回同一结果、聚合无意义）")
            LJ.judge(all_findings, on_log=lg.log, votes=_v)
            llm_calls = LJ.LC.USAGE.calls
            llm_cost = round(LJ.LC.USAGE.cny, 4)
            llm_cache_hits = LJ.LC.USAGE.hit_cache
            lg.log("[judge] " + LJ.cost_report().replace("\n", " | "))
            from collections import Counter
            lg.log("[judge] 分布 " + str(dict(Counter(f.ai_verdict for f in all_findings))))

        # ---- 判定一致性检查（开关 consistency-check；★ 默认只报不改）----
        if not args.no_consistency and all_findings:
            from core import consistency as CS
            cres = CS.check(all_findings)
            st = cres["stats"]
            lg.log(f"[consistency] 形态组 {st['n_shape_groups']} | "
                   f"同输入不同结论 {st['n_strict_inconsistent']}（应为 0）| "
                   f"★ 同形态主观层飘 {st['n_drift_groups']} 组")
            if args.consistency_downgrade and cres["drift"]:
                ch = CS.apply_downgrade(all_findings, cres)
                lg.log(f"[consistency] ★ 已降级 {len(ch)} 条 → needs_human"
                       f"（保守方向，会让更少的东西被报出去）")
                cres = CS.check(all_findings)      # 降级后重算，看还有没有
                lg.log(f"[consistency] 降级后：同形态飘 {cres['stats']['n_drift_groups']} 组")
            CS.write_report(rd / "consistency.md", cres)
            lg.log(f"[consistency] → consistency.md")

        R.write_findings(rd / "findings.tsv", all_findings)
        R.write_verdicts(rd / "verdicts.json", all_findings)
        R.write_findings_json(rd / "findings.json", all_findings)
        lg.log(f"[done] 总计 {len(all_findings)} 条 → {rd / 'findings.tsv'}")

    n_log, c_log = _cost_since(started)
    if n_log or c_log:
        llm_calls, llm_cost = n_log, c_log

    meta = {
        "tag": args.tag,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "elapsed_sec": round(time.time() - t0, 1),
        "kernel_stamp": _cfg_stamp(),
        "per_project": per_project,
        "n_findings": len(all_findings),
        "duality_enabled": not args.no_duality,
        "duality_note": "第 9 条判据（同函数内强弱写法并存）作为候选生成器接入；"
                        "已过「常量/净化」过滤。关掉用 --no-duality，用于单变量对照。",
        "llm_calls": llm_calls,
        "llm_cache_hits": llm_cache_hits,
        "llm_cost_cny": llm_cost,
        "llm_cost_note": "本轮实际付费（元）。判据与输入不变时重跑命中缓存 → 0；"
                         "若要报『判定一批要多少钱』，用首次未命中那一轮的值。",
        "llm_review": "AI 复核（非人工核实）",
        # ★★ 聚合策略必须写进来：实测单次跑的结论不可复现（docs/108），
        #    所以"vuln 有几个"这个数，离开"跑了几次、怎么合的"就没有意义。
        "judge_aggregation": {
            "votes_per_finding": max(1, args.judge_votes),
            "policy": "majority" if max(1, args.judge_votes) > 1 else "single",
            "tie_rule": "needs_human" if max(1, args.judge_votes) > 1 else None,
            "note": "同一条 finding 重复判会翻（docs/108：8 条里 4 条不稳）。"
                    "votes>1 时取多数票、平票判 needs_human（保守）；成本 ×votes。",
        },
        "human_minutes": None,        # ★ 人工时间必须手记（docs/95 §十⑤）
        "judge_oparg": os.environ.get("AF_JUDGE_OPARG", "0") == "1",
        "judge_oparg_note": "开关 AF_JUDGE_OPARG=1 时，判据补一条「同进程操作者自己提供的"
                            "输入（CLI 参数 / 本进程环境变量 / 本地配置）不算不可信输入」。"
                            "默认关 → 默认行为与历史轮次可比。",
        # ★★ 判据开关的**完整生效快照**（2026-10-12 补）
        #    为什么补：以前只记 judge_oparg → "这个数字是在哪把尺子下跑出来的"溯源不全，
        #    尤其是 AF_JUDGE_ARGCTX **默认是开的**，却一个字都没记（`docs/184` 复核时发现）。
        #    ★ 记的是**生效值**（环境变量为空时按模块默认），不是原样的环境变量。
        "judge_switches_effective": {
            "AF_JUDGE_ARGCTX": os.environ.get("AF_JUDGE_ARGCTX", "1") != "0",
            "AF_JUDGE_OPARG": os.environ.get("AF_JUDGE_OPARG", "0") == "1",
            "AF_JUDGE_REPOCFG": os.environ.get("AF_JUDGE_REPOCFG", "0") == "1",
            "AF_JUDGE_CFGSRC": os.environ.get("AF_JUDGE_CFGSRC", "0") == "1",
        },
        "judge_switches_note": "判定层判据补丁的生效快照（环境变量为空时按模块默认）。"
                               "★ 默认不等于全关：AF_JUDGE_ARGCTX **默认开**"
                               "（补「实参来源所在函数」的源码）。"
                               "改了任一开关的轮次，彼此不可直接比。",
        # ★★ 形态开关的完整快照（2026-10-12 补，C2 的一半）
        #    为什么补：`round-a1allforms` 这种"换了形态"的轮次，meta 里**一个字都没记**用的是哪几种
        #    → "这个靶挖过没挖过、用哪种形态挖的"无从查（`docs/184` §5 偏差 3 的根因之一）。
        #    ★ 记的是**生效值**（空环境变量按 gen_ql.py 的默认）。
        "sink_switches_effective": {
            "AF_SINKS_PATH": os.environ.get("AF_SINKS_PATH", "0") == "1",
            "AF_SINKS_HTTP": os.environ.get("AF_SINKS_HTTP", "0") == "1",
            "AF_SINKS_FS": os.environ.get("AF_SINKS_FS", "0") == "1",
            "AF_DUALITY_SDK": os.environ.get("AF_DUALITY_SDK", "0") == "1",
            "AF_SINKS_EXTRA": os.environ.get("AF_SINKS_EXTRA", "1") == "1",
            "AF_SINKS_DYNIMP": os.environ.get("AF_SINKS_DYNIMP", "0") == "1",
            "AF_PATH_FILTER": os.environ.get("AF_PATH_FILTER", "rel"),
        },
        "sink_switches_note": "候选生成侧（形态）开关的生效快照。"
                              "★ AF_SINKS_EXTRA=0 才是「空 extra」基线（与论文原包一致）；"
                              "AF_PATH_FILTER 默认 rel（修掉「目录名含 test 就整仓被排除」，docs/176）。",
    }
    # ★★ 从这里开始 `with R.ScanLog(...)` 已经退出 → `lg.log()` 会写**已关闭的句柄**。
    #    踩过（2026-10-12）：我把 C1/C2 接线放在 with 外面 → run_round 以 **EXIT=1** 结束，
    #    而且**只在"真跑一轮"时才暴露**（此前只测了重判路径的哈希不变）→ 改完管线必须真跑一次。
    def _safe_log(msg: str) -> None:
        try:
            if getattr(lg, "_fh", None) is not None and lg._fh.closed:
                print(msg)          # ★ 已关就直接 print（否则 lg.log 会先 print 再抛 → 打两遍）
                return
            lg.log(msg)
        except (ValueError, AttributeError):
            print(msg)

    # ---- ★ C1 候选级上游核查（默认开）------------------------------------------
    # 只查要报出去的（vuln）；只写 upstream.json 当证据，**绝不改判定**。
    #   ★ 接在这里而不是"想起来才手动跑"：这条债拖了三次（docs/184 §5 偏差 3）。
    #   ★ 失败不阻断本轮 —— 网络/限流不该让一整轮 CodeQL 白跑。
    #   ★★ 摘要进 meta.json（扫完的文件里那份 scan.log 已关闭，不留痕就查不着）。
    up_sum = None
    if not args.no_upstream and all_findings:
        try:
            from core import upstream as UP
            res = UP.run_round_dir(rd, on_log=_safe_log)
            up_sum = {
                "checked": len(res),
                "still_present": sum(1 for v in res.values() if v.get("still_present") is True),
                "gone": sum(1 for v in res.values() if v.get("still_present") is False),
                "archived": sum(1 for v in res.values() if v.get("archived")),
                # ★★ "没查成"必须单列（docs/178 #8：它被错打成"上游文件已不存在"过）
                "not_checked": sum(1 for v in res.values() if v.get("error")),
            }
        except Exception as e:
            up_sum = {"error": f"{type(e).__name__}: {e}"}
            _safe_log(f"[upstream] ★ 核查失败（不阻断本轮）：{up_sum['error']}")
        if up_sum is not None:
            meta["upstream"] = up_sum

    R.write_meta(rd / "meta.json", meta)
    print(f"\n== round done: {len(all_findings)} findings, {meta['elapsed_sec']}s → {rd}")

    # ---- ★ C2 目标台账记账（默认开）-------------------------------------------
    # "这个靶挖过没、用哪种形态挖的" —— 起新一轮之前用 `core/ledger.py --check` 查它。
    #   ★ 必须在 write_meta 之后：record_from_round 要读 meta.json。
    if not args.no_ledger:
        try:
            from core import ledger as LD
            LD.record_from_round(rd, on_log=_safe_log)
        except Exception as e:
            _safe_log(f"[ledger] ★ 记账失败（不阻断本轮）：{type(e).__name__}: {e}")

    # ---- ★ 候选台账记账（默认开）------------------------------------------------
    # "这一条候选我看到哪一步了" —— 只追加 `seen` 事件，**幂等**（同一轮跑两次不会重复记）。
    #   ★ 与上面的「目标台账」是两回事：那个记**靶**，这个记**候选**（见 core/candidate_ledger.py 头注释）。
    #   ★ 同样失败不阻断 —— 账本是辅助信息，不是判据。
    if not args.no_cand_ledger:
        try:
            from core import candidate_ledger as CL
            rc = CL.cmd_add_round(args.tag)
            _safe_log(f"[cand-ledger] 候选台账记账完成（rc={rc}）")
        except Exception as e:
            _safe_log(f"[cand-ledger] ★ 记账失败（不阻断本轮）：{type(e).__name__}: {e}")

    return 0 if all_findings else 2


if __name__ == "__main__":
    raise SystemExit(main())
