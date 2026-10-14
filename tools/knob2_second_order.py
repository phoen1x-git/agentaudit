# -*- coding: utf-8 -*-
"""★★★ 旋钮二：二阶触发（跨轮次污点）

论文自己承认的空白
==================
AgentFuzz 做的是「一句话丢进去，看它有没有打穿」—— **单次交互**。
旋钮二把它拉长成两段：

    第一次交互：把某个东西**存进去**（存进记忆/ 文件 / 数据库）
    第二次交互：再把它**引爆**

★★ 机制一点没变（还是「输入流到危险操作」），只是中间多了个中转站。

═══ 为什么这个旋钮能直接复用基础架构 ═══
判定层的输入是「**证据 + 判据**」，与漏洞类型无关。
旋钮二要改的只有两样：
  ① **证据格式**：加上「上一轮存了什么」
  ② **prompt里的判据描述**：第一层从「有没有多用户」扩成
     「**这个输入是不是上一轮存的、有没有跨会话存活**」
★ 代码不用动 —— 这就是在验证「基础建完能不能批量做旋钮」。

═══ 为什么先做这个 ═══
① 论文里明写「我们不处理这类」→ **对手把地盘空出来了**
② 二阶污点那条线我10-03~10-04 已经跑过四轮，有现成的实验设计
③ 已有硬数据：**33 条模型自主生成的 filter，含危险操作 0 条**
   → 这个负结果本身就是论文的一个论点

═══ 这一步先做什么 ═══
**Step 1：把「二阶」这个概念落成可操作的判据。**
先不跑实验 —— 先回答「怎么判一个端点是不是二阶的」。
"""
import io
import json
import os
import re
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm_client as LC
import llm_judge as J

POOL = J.POOL


# ══════════════════════════════════════════════════════════════════
# ★★ 信号词表 —— 这里踩了第二个坑：第一版词太宽，等于没筛
#──────────────────────────────────────────────────────────────────
# 第一版是 `save|store|write|append|load|read|get|fetch|recall|...`
# 结果**每个文件都是「存6读6喂6」**—— 因为
#   `get`/`list`/`read`/`save` 这种词在 Python 代码里满地都是
#   （getattr、get_user、list_tasks、readme…）
# ★ 教训：**信号词要用「具体的持久化动作」，不是「泛化的数据访问动词」**。

# ★ 存：真正把东西写进「跨轮次存活」的载体
STORE_PAT = re.compile(
    # 显式的记忆/会话持久化API
    r"(memory_store|memory\.(add|append|save|update|set)|"
    r"\.save\(|save_memory|store_memory|add_memories|"
    r"conversation_history\.(add|append|save)|save_conversation|"
    r"persist|upsert|checkpoint|snapshot|"
    # 落盘（写文件/写库）—— 排除只读模式
    r"\.write_text\(|\.write_bytes\(|open\([^)]*['\"][wax]|"
    r"\.insert\(|\.update\(|executemany|commit\(\))",
    re.I)

# ★ 读：从载体里取回来（且不是「读一个常量」）
RETRIEVE_PAT = re.compile(
    r"(memory_store\.(get|all|search|recall|query)|"
    r"\.get_memories|search_memories|recall_memories|"
    r"conversation_history\.(get|all|query)|get_conversation|"
    r"load_memory|read_memory|fetch_history|"
    r"\.load\(|json\.load\(|read_text\(|read_bytes\(|"
    r"\.select\(\)|\.fetchall\(\)|\.fetchone\(\)|\.query\()",
    re.I)

# ★★ 喂回模型 —— 三者里**最重要**的，必须是明确的「拼进 prompt」
FEEDBACK_PAT = re.compile(
    r"(prompt\s*\+=|prompt\s*=\s*[\w_]*\s*\+|messages\s*\+=|"
    r"messages\.append\(|history\.append\(|context\s*\+=|"
    r"_build_prompt|build_prompt|get_conversation_prompt|"
    r"system_prompt\s*\+|input_text\s*=|f\"[^\"]*\{(history|messages|memory|"
    r"conversation|past)[^\"]*\}\"|"
    r"(history|messages|memory|conversation)[\w.]*\s*\+\s*)",
    re.I)

# ★ 危险操作（从 ast_criteria 的 cell 定义搬过来，保持一致）
DANGER_OPS = {
    "exec_code": r"(eval\(|exec\(|compile\(|__import__)",
    "subprocess": r"(subprocess\.|os\.system|os\.popen|popen)",
    "sql": r"(cursor\.execute|\.execute\(|INSERT INTO|UPDATE .* SET)",
    "file_write": r"(open\([^)]*['\"]w|\.write_text\(|\.write\(|shutil\.)",
    "shell": r"(shell=True|os\.system|Popen\()",
}


def find_second_order_signals(path, src):
    """在单个文件里找「存 → 取回 → 喂给模型」的迹象。

    ★★★ 这里踩过一个严重的坑：**用「存次数 × 读次数 × 喂次数」当分数**
       等于按文件行数排序 —— 实测 Clawith 的 `agent_tools.py`（大文件）
       拿到 764667 分，是第二名的 10 倍，但它只是**行数多**。
       → 大文件会把所有真候选挤掉。

    ★ 正确做法：**要求三类信号在同一批函数/类里出现**。
       二阶的本质是**数据流闭合**，而数据流闭合只可能发生在
       一个具体的处理流程里，不会均匀散布在几百个函数中。
       所以：按函数切块，**只在单个块内同时出现存+读+喂**才算候选。
    """
    import ast
    out = []
    lines = src.splitlines()
    try:
        tree = ast.parse(src)
    except Exception:
        return out

    # ★★ 只看函数/方法级 —— `<module>` 块包住整个文件，
    #    三类信号必然都在里面，等于「这个文件有嫌疑」而不是
    #    「这个处理流程里有二阶嫌疑」。
    #★ 二阶的本质是**数据流在某个具体流程里闭合**，不是「这个文件很大」。
    funcs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.lineno
            b = getattr(node, "end_lineno", a) or a
            funcs.append((node.name, a, b, node))
    # ★ 文件太小（< 40 行）的块没有分析价值
    funcs = [x for x in funcs if (x[2] - x[1] + 1) >= 4]

    # 全文件的危险操作行，供打分用
    dang_all = {}
    for name, pat in DANGER_OPS.items():
        hits = [i for i, l in enumerate(lines, 1) if re.search(pat, l)]
        if hits:
            dang_all[name] = hits

    # ★★★ 第三个坑：「三类信号必须在同一函数内」也**太严了** ——
    #   实测只剩 4 个候选，而且都不像真的。
    #   原因：**二阶的数据流天然跨函数** —— 一个函数负责存、
    #   另一个负责读回、再另一个负责拼 prompt。这正是真实 Agent 的写法。
    #
    # → 正确的粒度：**文件内聚合**，但要求
    #   ① 有真正的存储动作（写文件/写库/记忆 API，不是泛化的动词）
    #   ② 有真正的取回动作
    #   ③ 有明确的「拼进 prompt」
    #   ④ ★ 三者在**行号上接近**（同一段流程内，比如相差 60 行以内）
    #      —— 太远就说明不是同一条数据流

    best = []
    for name, a, b, node in funcs:
        seg = lines[a - 1:b]
        if len(seg) < 4:
            continue
        stores, reads, feeds = [], [], []
        for i, l in enumerate(seg, a):
            if re.match(r"\s*(import|from|#)", l):
                continue
            if STORE_PAT.search(l):
                stores.append(i)
            if RETRIEVE_PAT.search(l):
                reads.append(i)
            if FEEDBACK_PAT.search(l):
                feeds.append(i)
        dang = {}
        for dn, dl in dang_all.items():
            inside = [x for x in dl if a <= x <= b]
            if inside:
                dang[dn] = inside[:5]
        best.append({
            "func": name, "start": a, "end": b,
            "n_lines": b - a + 1,
            "stores": stores, "reads": reads, "feeds": feeds,
            "danger": dang, "n_dang": sum(len(v) for v in dang.values()),
        })

    if not best:
        return out

    # ★★ 文件内聚合：找「有存的块」和「有喂的块」距离最近的组合
    have_st = [h for h in best if h["stores"]]
    have_rd = [h for h in best if h["reads"]]
    have_fd = [h for h in best if h["feeds"]]
    if not (have_st and have_rd and have_fd):
        return out

    dang_file = {}
    for dn, dl in dang_all.items():
        dang_file[dn] = dl[:6]

    # 选距离最近的一对（存块↔ 喂块）
    def dist(h1, h2):
        return abs(h1["start"] - h2["start"])

    pair = None
    for h1 in have_st:
        for h2 in have_fd:
            d = dist(h1, h2)
            if pair is None or d < pair[0]:
                pair = (d, h1, h2)
    if pair is None:
        return out
    d, h1, h2 = pair

    # ★ 距离门槛：存和喂相隔 400 行以上就不算同一条数据流
    if d > 400:
        return out

    rd = min(have_rd, key=lambda h: min(abs(h["start"] - h1["start"]),
                                        abs(h["start"] - h2["start"])))
    out.append({
        "file": path, "n_lines": len(lines),
        "store_func": h1["func"], "store_at": h1["start"],
        "read_func": rd["func"], "read_at": rd["start"],
        "feed_func": h2["func"], "feed_at": h2["start"],
        "dist": d, "n_lines_span": max(h1["end"], h2["end"]) - min(h1["start"], h2["start"]),
        "stores": h1["stores"][:6] + rd["stores"][:4],
        "reads": rd["reads"][:6],
        "feeds": h2["feeds"][:6],
        "danger": dang_file,
        "n_dang": sum(len(v) for v in dang_file.values()),
        # ★ 分数：不是行数，而是「数据流闭合的质量」
        "score": (30 if dang_file else 0) + max(0, 30 - d // 20)
                 + min(len(h2["feeds"]), 3) * 5,
    })
    return out


# ★★ 测试文件的两种形态都要排除（10-07 踩到）：
#    ① 路径形态  /tests/ /test/ /examples/ /mock
#    ② ★★ **命名形态** test_xxx.py / xxx_test.py / conftest.py
#       —— 只排路径的话，`test_api_app.py` 这种放在 src 里的照样进来。
#       实测 OpenBiliClaw 的最高分候选就是 `test_api_app.py`，
#       而它的 score 是第二名的 10 倍 —— 不排的话整个旋钮二都测的是测试代码。
TEST_PATH = re.compile(r"(^|/)(tests?|examples?|mocks?|samples?|fixtures?|"
                       r"benchmarks?|docs?)(/|$)", re.I)
TEST_NAME = re.compile(r"(^test_|_test\.py$|^conftest\.py$|"
                       r"^mock_|_mock\.py$|test_.*\.py$)", re.I)


def is_test_or_demo(path):
    p = path.replace("\\", "/")
    return bool(TEST_PATH.search(p) or TEST_NAME.search(os.path.basename(p)))


def scan_project(repo, branch):
    import recheck
    f, n, miss = recheck.cache_files(repo, branch)
    if not f:
        return []
    hits = []
    for fp, src in f.items():
        if not fp.endswith(".py"):
            continue
        low = fp.lower()
        # ★ 生产代码才看 —— ★★ 路径和命名两种形态都要排
        if is_test_or_demo(fp):
            continue
        if "/scripts/" in low or "/vendors/" in low or "/third_party/" in low:
            continue
        hits.extend(find_second_order_signals(fp, src))
    return hits


# ══════════════════════════════════════════════════════════════════
# 第二步：让 LLM 判「这是不是二阶」
# ══════════════════════════════════════════════════════════════════
RUBRIC_KNOB2 = """你是一个 Agent 项目「跨轮次污点（二阶）」的判定员。

★ 什么是二阶（这是本次判定的全部依据）
----------------------------------------
一阶漏洞：外部输入 → 直接流到危险操作。**一次交互就完成**。

二阶漏洞：**分两次**——
  第一次交互：外部输入被**存起来**（写进记忆 / 文件 / 数据库 / 会话历史）
  第二次交互：存起来的内容被**读回来**，并且**当成指令或数据喂给模型**，
            最终流到危险操作。

★★ 二阶的三个必要条件（缺一不可）：
  ① **能存**：外部输入能落进某个持久的载体
  ② **跨轮次存活**：这个载体在下一轮交互里还能被读到
  ③ ★ **影响行为**：读回来的内容**真的进了 prompt / messages / 工具入参**，
     而不只是被展示给人看

★★ 最常见的误判（务必避开）：
  · 「能写文件」但从不读回来 → 不是二阶
  · 「能写文件」但读回来只是给用户看 → 不是二阶
  · 「存进数据库」但下一轮从不查 → 不是二阶
  ★ 判据是**数据流真的闭合**，不是「有存储功能」。

输出 JSON：
{
  "has_store": "yes|no",
  "has_cross_turn": "yes|no|unclear",
  "influences_behavior": "yes|no|unclear",
  "danger_ops_reachable": ["exec_code|subprocess|sql|file_write|shell", ...],
  "verdict": "second_order|risk|risk_unclear",
  "confidence": 0.0-1.0,
  "evidence": "一句话，引用具体代码行",
  "one_line": "一句话结论"
}

判定尺度：
- verdict = second_order   三个条件**都yes**且能到达危险操作
- verdict = risk           存 + 跨轮次是 yes，但「是否影响行为」或
                           「能否到达危险操作」说不清→ ★ 有风险但没闭环
- verdict = risk_unclear   信息不足（比如没看到读回来的那段代码）
★ 信息不足时给 risk_unclear 并如实降低 confidence，
  **不要为了给答案而把条件凑齐**。"""


def judge_second_order(repo, branch, hits, max_files=6):
    import recheck
    f, n, miss = recheck.cache_files(repo, branch)
    out = []
    for h in hits[:max_files]:
        src = f.get(h["file"])
        if not src:
            continue
        L = src.splitlines()
        # ★ 给 LLM 看：存/读/喂的关键行 + 危险操作行
        marks = sorted(set(h["stores"][:4] + h["reads"][:4] + h["feeds"][:4]
                           + [x for v in h["danger"].values() for x in v[:2]]))
        if not marks:
            continue
        code = []
        for i in marks[:22]:
            if 0 < i <= len(L):
                code.append("%5d| %s" % (i, L[i - 1][:112]))
        user = ("【项目】%s（%s）\n【文件】%s（%d 行）\n\n"
                "【关键行：存 / 读 / 喂回模型 / 危险操作】\n%s\n\n"
                "文件里的信号统计：存 %d 处、读 %d 处、喂给模型 %d 处、危险操作 %s\n\n"
                "请按三个必要条件判定这是不是二阶漏洞。"
                % (repo, h["file"], h["file"], h["n_lines"], "\n".join(code),
                   len(h["stores"]), len(h["reads"]), len(h["feeds"]),
                   json.dumps(h["danger"], ensure_ascii=False)))
        try:
            r = LC.ask_json(RUBRIC_KNOB2, user, tag="knob2", max_tokens=3600)
        except Exception as e:
            continue
        r["_repo"] = repo
        r["_file"] = h["file"]
        r["_signals"] = h
        out.append(r)
    return out


def main():
    recs = J.load_recs()
    targets = sorted({v.get("_repo") for v in
                      json.load(open(os.path.join(POOL, "llm_verdict.json"),
                                   encoding="utf-8")).values()} - {None})
    print("★ 旋钮二 · Step 1：找「存 → 读 → 喂回模型」的信号\n")
    print("%-34s %-8s %s" % ("项目", "候选文件", "信号分布"))
    print("-" * 74)
    allres = []
    for repo in targets:
        rec = recs.get(repo)
        br = (rec.get("branch") if rec else None) or "main"
        hits = scan_project(repo, br)
        if not hits:
            continue
        hits.sort(key=lambda h: -h["score"])
        print("%-32s %-5d 最高分 %-5d %s"
              % (repo.split("/")[-1][:32], len(hits), hits[0]["score"],
                 hits[0]["file"].split("/")[-1][:28]))
        for h in hits[:3]:
            print("      %-26s 存@%-5s 读@%-5s 喂@%-5s 距%-4d 危%d"
                  % (h["file"].split("/")[-1][:26], h["store_at"],
                     h["read_at"], h["feed_at"], h["dist"], h["n_dang"]))
        #★★★这一行曾经被我自己的编辑删掉了 → allres 永远是空列表，
        #   但日志照样打印「候选写入」——看起来一切正常、实际产出是空的。
        #   ★ 教训：**日志说"写入了"不等于真写入了**，要回读文件确认。
        allres.append((repo, br, hits))

    #★★ 注意：hit 里已经没有 `func` 键了（改成了 store_func/read_func/feed_func），
    #   取 `h["func"]` 会 KeyError —— 而异常曾被 `2>&1 | tail` 吞掉，
    #   导致「看起来跑完了，其实 JSON 是空的」。**回读确认的习惯又一次救了我。**
    json.dump([{"repo": r, "branch": b,
                "hits": [{"file": h["file"], "score": h["score"],
                          "store_func": h["store_func"],
                          "read_func": h["read_func"],
                          "feed_func": h["feed_func"],
                          "store_at": h["store_at"], "read_at": h["read_at"],
                          "feed_at": h["feed_at"], "dist": h["dist"],
                          "n_st": len(h["stores"]), "n_rd": len(h["reads"]),
                          "n_fd": len(h["feeds"]), "n_dang": h["n_dang"],
                          "danger": h["danger"]}
                         for h in hs]}
               for r, b, hs in allres],
              open(os.path.join(POOL, "knob2_candidates.json"), "w",
                   encoding="utf-8"), ensure_ascii=False, indent=1)

    print("\n候选写入 %s" % os.path.join(POOL, "knob2_candidates.json"))
    print("下一步：Step 2 让 LLM 判「三个条件是否都成立」")
    if os.environ.get("KNOB2_STEP2") != "1":
        print("（设 KNOB2_STEP2=1 才跑 Step 2，要花钱）")
        return
    step2(allres)


def step2(allres):
    """★ Step 2：把候选交给 LLM 判「三个必要条件是否都成立」。

    ★ 这一步证明的是：**旋钮换判据不用改代码，只改 prompt**。
      判定层的骨架（缓存/记账/成本/证据格式）完全复用。
    """
    import recheck
    from collections import Counter
    print()
    print("=" * 70)
    print("★ Step 2：LLM 判「三个必要条件」")
    print("=" * 70)
    outp = os.path.join(POOL, "knob2_verdict.json")
    done = json.load(open(outp, encoding="utf-8")) if os.path.exists(outp) else {}

    for repo, br, hits in allres:
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            continue
        for h in hits:
            key = "%s|%s" % (repo, h["file"])
            if key in done:
                continue
            src = fmap.get(h["file"])
            if not src:
                continue
            L = src.splitlines()
            marks = sorted(set(
                h["stores"][:4] + h["reads"][:4] + h["feeds"][:4]
                + [x for v in h["danger"].values() for x in v[:2]]))[:24]
            code = ["%5d| %s" % (i, L[i - 1][:112])
                    for i in marks if 0 < i <= len(L)]
            user = ("【项目】%s\n【文件】%s（%d 行）\n\n"
                    "【关键行：存 / 读 / 喂回 prompt / 危险操作】\n%s\n\n"
                    "信号定位：存 在第 %s 行、读 在第 %s 行、喂 在第 %s 行"
                    "（相隔 %d 行）\n危险操作：%s\n\n"
                    "请按三个必要条件判定这是不是二阶漏洞。"
                    % (repo, h["file"], h["n_lines"], "\n".join(code),
                       h["store_at"], h["read_at"], h["feed_at"], h["dist"],
                       json.dumps(h["danger"], ensure_ascii=False)))
            try:
                r = LC.ask_json(RUBRIC_KNOB2, user, tag="knob2", max_tokens=3600)
            except Exception as e:
                print("  ★ %s 失败 %s" % (repo.split("/")[-1][:20], str(e)[:44]))
                continue
            r["_repo"] = repo
            r["_file"] = h["file"]
            r["_dist"] = h["dist"]
            r["_n_dang"] = h["n_dang"]
            done[key] = r
            json.dump(done, open(outp, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
            print("  %-28s %-14s conf=%.2f %s"
                  % (h["file"].split("/")[-1][:28], r.get("verdict"),
                     r.get("confidence", 0), (r.get("one_line") or "")[:50]))

    print()
    print("Step 2 完成 %d 处，花费 %.4f 元" % (len(done), LC.USAGE.cny))
    print("分布：" + json.dumps(
        dict(Counter(v.get("verdict") for v in done.values())),
        ensure_ascii=False))


if __name__ == "__main__":
    main()