"""检验「命中 ⟺ locus 里的 sink 函数名 ∈ 我们的 sinks.yml」这条判据。

对每个已有分诊结果的靶：
  · 预测 = 该 positive 的 sink 类 locus 里，**至少有一个函数名在我们的表里**
  · 实测 = 分诊 JSON 里的 HIT
→ 打印 预测 vs 实测 的混淆矩阵。

用法:
  python tools/predict_hitrate.py
"""
import glob
import json
import os
import re

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
D = os.path.join(PROJ, "data", "target_pool")

# 分诊结果文件 → (靶 repo, 轮次说明)
GAPS = {
    "tp2x_gap_ak5.json": "wxy2ab__akinterpreter",
    "tp2x_gap_ph5.json": "agno-agi__phidata",
    "tp2x_gap_rg.json": "RAG-Gym__RAG-Gym",
    "tp2x_gap_vb2.json": "firetix__vibe-coding-penetration-tester",
    "tp2x_gap_vi.json": "cnsdqd-dyb__VillagerAgent-Minecraft-multiagent-framework",
    "tp2x_gap_ac.json": "FSoft-AI4Code__AgileCoder",
    "tp2x_gap_sf.json": "disler__single-file-agents",
    "tp2x_gap_mm.json": "microsoft__MM-REACT",
    "tp2x_gap_ag.json": "shibing624__agentica",
    "tp2x_gap_gt.json": "open-compass__GTA",
}

# ★ 注意：不要在这里列 `get`/`post`/`run` —— 它们**同时是我们 sink 表里的名字**
#   （`requests.get/post`、`subprocess.run`）。第一版把它们当"source 点"剔掉了
#   → AgileCoder 的 4 条被误判成"预测否"（实际 locus 里就有 `get`）。
#   判据应当是：**只要 locus 里有名字在我们表里，就算覆盖**。
SOURCE_FN = {"create", "one_chat", "text_chat", "chat", "completion", "invoke",
             "stream", "generate", "understand_image", "chat_completion",
             "arun", "respond", "reply", "ask", "forward", "map_response"}


def load_sinks():
    """sinks.yml 里**默认生效**的 sink 名集合（group 为空的 + paper 全量）。"""
    cfg = yaml.safe_load(open(os.path.join(PROJ, "core", "config", "sinks.yml"),
                              encoding="utf-8"))
    names = set()
    for s in cfg["sinks"]:
        if s.get("group"):
            continue          # 默认关的组（fs/path/http/dynimp）不算
        if s.get("name"):
            names.add(str(s["name"]))
        if s.get("func"):
            names.add(str(s["func"]))
    return names


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="any", choices=["any", "last", "first"],
                    help="any=任一 locus 在表里；last=**最后一个**（locus 疑似按 source→sink 排序）；first=第一个")
    a = ap.parse_args()

    sinks = load_sinks()
    print(f"默认生效的 sink 名（{len(sinks)} 个）: {sorted(sinks)}")
    print(f"模式: {a.mode}")
    print()
    tot = [[0, 0], [0, 0]]
    for fn, repo in GAPS.items():
        p = os.path.join(D, fn)
        if not os.path.exists(p):
            print(f"（缺 {fn}）")
            continue
        d = json.load(open(p, encoding="utf-8"))
        rows = [r for r in d.get("rows", []) if r.get("kind", "positive") == "positive"]
        if not rows:
            print(f"（{fn} 无 positive 行）")
            continue
        tp = fp = fn2 = tn = 0
        for r in rows:
            loci = r.get("loci") or []
            names = []
            for s in loci:
                m = re.search(r"\(([^)]*)\)\s*$", s)
                nm = (m.group(1) if m else "").strip()
                names.append(nm)
            if a.mode == "last":
                cand = [names[-1]] if names else []
            elif a.mode == "first":
                cand = [names[0]] if names else []
            else:
                cand = names
            pred = any(n and n in sinks for n in cand)
            # ★ 口径要跟判据对齐：判据说的是"**能命中 locus 那个点**"，
            #   所以"实测"必须用**严格口径**（`HIT  命中` = 位置匹配），
            #   不能算 `HITf 文件级命中`（同文件里有别的 vuln，松口径）。
            #   （踩过：disler 的 10 条 HITf 被当成 HIT → 一致率假跌到 44%）
            _c = str(r.get("cat", ""))
            actual = _c.startswith("HIT") and not _c.startswith("HITf")
            if pred and actual:
                tp += 1
            elif pred and not actual:
                fp += 1
            elif (not pred) and actual:
                fn2 += 1
            else:
                tn += 1
        n = len(rows)
        print(f"=== {repo} (positive {n}) ===")
        print(f"   预测命中&实测命中 {tp:<3} | 预测命中&实测否 {fp}")
        print(f"   预测否&实测命中   {fn2:<3} | 预测否&实测否 {tn}")
        acc = (tp + tn) / n * 100 if n else 0
        print(f"   → 一致率 {acc:.0f}%（{tp+tn}/{n}）")
        tot[0][0] += tp
        tot[0][1] += fp
        tot[1][0] += fn2
        tot[1][1] += tn
        print()
    s = sum(sum(x) for x in tot)
    if s:
        acc = (tot[0][0] + tot[1][1]) / s * 100
        print(f"★ 合计一致率 {acc:.0f}%（{tot[0][0]+tot[1][1]}/{s}）"
              f"  误报 {tot[0][1]} / 漏报 {tot[1][0]}")


if __name__ == "__main__":
    main()
