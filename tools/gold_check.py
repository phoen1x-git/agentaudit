# -*- coding: utf-8 -*-
"""★ gold set 校准 —— 判定层的「回归测试」。

★★ 为什么这是整个判定层最重要的一步
--------------------------------------
判定 prompt 是个**需要反复调的东西**（判据措辞、示例、层序都会改）。
但「改prompt 之后判定质量是变好还是变坏」**没有客观标准** ——
除非有一组**已知答案**做基准。

★ 我已经有 4 个人工核实过的项目（`llm_judge.GOLD`），
  它们的结论是**我逐条读源码得出的**。
  → 每次改 prompt 都跑一遍，看结论有没有翻转。
     翻转了 → 要么 prompt 改坏了，要么我的 gold 错了。
     ★ 实测真出现过：两个模型都认为 astra 的 /api/all 是敏感接口，
       而我的人工结论是「作者明示公开」——**复核后发现是我错了**
       （旁边挂鉴权的 /api/v1/cache/ledger 就在隔壁）。

★ 所以 gold set 是**双向**的：
  ① 用来验 prompt 改动有没有搞坏判定
  ② ★ 用来发现**我的人工结论本身错了**
"""
import io
import json
import os
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm_client as LC
import llm_judge as J
import recheck

POOL = J.POOL
OUT = os.path.join(POOL, "gold_check.json")

# ★ 每个 gold 项允许的结论集合 —— 因为一个项目里不同端点可以有不同结论，
#   严格到「每处都必须 not_vuln」会误报（LLM 判得保守也是对的）。
#   但**整项目的分布**必须有 not_vuln 占多数，否则说明尺度跑偏了。
EXPECT = {
    "rhesis-ai/rhesis": dict(
        expect_all="not_vuln",
        note="全局字典无 owner + docstring 明写 local demo",
        allow_vuln=0),
    "0xethanq/astra-quant-agent": dict(
        expect_all=None,          # ★ 有争议 —— 见下方「争议项」
        note="7 处中 5 处是行情/版本号（not_vuln），但 /api/all 与 /api/overview "
             "旁边就是挂鉴权的 /api/v1/cache/ledger → 可能真有洞",
        allow_vuln=2),
    "dataelement/Clawith": dict(
        expect_all="not_vuln",
        note="密码链路防枚举+ 一次性token；真改密码接口有 Depends",
        allow_vuln=0),
    "agentuniverse-ai/agentUniverse": dict(
        expect_all="not_vuln",
        note="service_id 只能取已注册服务；importlib 来自配置文件",
        allow_vuln=0),
}


def main():
    per = int(os.environ.get("GOLD_PER_REPO", "3"))
    recs = J.load_recs()
    bad = []
    print("=" * 72)
    print("★ gold set 校准（每项目 %d 处，模型=%s）" % (per, LC.MODEL))
    print("=" * 72)

    for repo, rule in EXPECT.items():
        rec = recs.get(repo)
        if not rec:
            print("  ! %s 不在批次里" % repo)
            continue
        evs = (rec.get("evidence", {}).get("unauth_endpoint") or [])[:per]
        br = rec.get("branch") or "main"
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            print("  ! %s 取不到源码" % repo)
            continue
        ctx = J.fmt_ctx(repo, J.build_context(rec, fmap))

        print("\n--- %s" % repo)
        print("    gold 依据：%s" % rule["note"])
        verdicts = []
        for ev in evs:
            body = J.get_body(fmap, ev)
            user = ctx + "\n\n" + J.fmt_item(ev, body) + \
                "\n\n请按三层判据判断这个命中是不是真漏洞。"
            try:
                r = LC.ask_json(J.RUBRIC, user, tag="gold", max_tokens=3600)
            except Exception as e:
                print("    ★ 失败：%s" % str(e)[:60])
                bad.append((repo, ev["line"], "ERR"))
                continue
            v = r.get("verdict", "?")
            verdicts.append(v)
            print("    %-30s %-12s conf=%.2f  %s"
                  % (ev.get("route", "-")[:30], v, r.get("confidence", 0),
                     (r.get("one_line") or "")[:52]))

        # 分布检查
        n_v = verdicts.count("vuln")
        if rule["expect_all"] and verdicts and n_v == 0:
            print("    ✓ 全部 not_vuln，符合 gold")
        elif verdicts and rule["allow_vuln"] is not None:
            if n_v <= rule["allow_vuln"]:
                print("    ✓ vuln %d 处，在允许范围内（≤%d）"
                      % (n_v, rule["allow_vuln"]))
            else:
                print("    ★ vuln %d 处 > 允许的 %d" % (n_v, rule["allow_vuln"]))
                bad.append((repo, "-", "vuln 超出允许范围 %d" % rule["allow_vuln"]))

    print("\n" + "=" * 72)
    print("花费：" + LC.USAGE.report())
    print()
    if bad:
        print("★ 需要处理 %d 项：" % len(bad))
        for b in bad:
            print("   %s  %s" % (b[0].split("/")[-1], b[1:]))
        print("\n★ 分两种情况：")
        print("  · prompt 改坏了 → 改回来")
        print("  · ★ gold 本身错了 → 改 gold（这是好事，说明 LLM 发现了我的错）")
    else:
        print("全部通过：判定尺度与人工结论一致。")
    json.dump({"bad": bad, "usage": LC.USAGE.cny,
               "model": LC.MODEL},
              open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()