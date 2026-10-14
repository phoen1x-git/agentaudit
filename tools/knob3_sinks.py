# -*- coding: utf-8 -*-
"""★★★ 旋钮三：危险出口清单加长

论文原文（`论文框架内的五个旋钮.md`第 43 行）
──────────────────────────────────────────────────
「论文的检测器是照着**一张人工列的危险操作清单**去扫代码的，
  主要盯着三类：执行系统命令、读写文件、把一段字符串当代码执行。
  这张清单不是天上掉下来的，是作者手工定的。
  **既然是手工定的，就能加长。**
  你们可以往里添：把数据发到外部网址（这是数据外泄）、
  往数据库里写、发邮件发消息、调外部接口。」

★ 为什么这个旋钮成本最低
  论文原文：「改的就是那张清单，**代码结构一点不用动**」。

═══ 现有清单 vs 论文建议加的 ═══
现有（`ast_criteria.EXEC_FUNCS` + `CLIENT_FUNCS`）：
  执行类  eval/exec/subprocess/pickle/yaml.load/...
  客户端类 OpenAI/Anthropic/requests/httpx/aiohttp/urlopen

★ 论文建议加的四类里，**后两类完全没有**：
  ✗ 写数据库
  ✗ 发邮件 / 发消息（Slack/微信/钉钉/Telegram）
而 `CLIENT_FUNCS` 虽然有 requests/httpx，
但**它只判「调外部接口」，没区分「是读还是写」** ——
数据外泄和外部接口调用其实是两个不同的严重性。

═══ 这一版做什么 ═══
Step 1  建立**扩展出口清单**（原清单 + 四类新增）
Step 2  在同一批 30 个项目上跑，看**新增了多少命中**
Step 3  ★ 关键是分清：**新增的命中是「真能到」还是「只是用了这个 API」**

★ 这一步最容易被糊弄过去：「项目里用了 smtplib」≠「能发邮件泄露数据」。
   所以必须配 LLM 判定（复用判定层，只换判据 —— 这正是基础架构的复用点）。
"""
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast_criteria as A
import llm_client as LC
import llm_judge as J

POOL = J.POOL
OUT = os.path.join(POOL, "knob3_sinks.json")

# ══════════════════════════════════════════════════════════════════
# ★ 扩展出口清单 —— 论文点名的四类
# ══════════════════════════════════════════════════════════════════
# 每条都带「分类」，因为**分类决定严重性**，不是数量
NEW_SINKS = {
    # ① 写数据库（论文明确建议）
    "db_write": [
        r"\.execute\s*\(\s*[\"'`]?\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)",
        r"\.executemany\s*\(",
        r"\binsert_many\s*\(|\binsert_one\s*\(|\bbulk_write|\bsave\s*\(\s*dict",
        r"\.update_one\s*\(|\.update_many\s*\(|\.delete_one\s*\(|\.delete_many\s*\(",
        r"\.replace_one\s*\(|\.find_one_and_update\s*\(",
        r"\bcommit\s*\(\s*\)",         # ★ 写事务提交（与查询区分）
    ],
    # ② 发邮件（论文明确建议）
    "email": [
        r"\bsmtplib\b|\bsmtpd\b", r"\bMIMEText\b|\bEmailMessage\b",
        r"\bsend_mail\b|\bsendmail\b|\bsend_message\b|"
        r"\bsend_email\b|\bmail\.send\b|\bEmailMultiAlternatives\b",
    ],
    # ③ 发消息 / IM / webhook（论文明确建议）
    "messaging": [
        r"\bsend_message\b.*(slack|discord|telegram)",
        r"\bWebhookClient\b|\bwebhook\b.*\b(post|send)\b",
        r"\bBot\b.*\bsend\b|send_to\(|push_message|send_chat_message",
        r"\bsocket\.sendall\b|\bwebsocket\.send\b",
        r"\bdingtalk\b|\bwechat.*work\b|\bfeishu\b|\blark\b",
    ],
    # ④ ★ 数据外泄（外部传输）—— 与 CLIENT_FUNCS 的区别是
    #    ★ **必须带数据**，而不是仅仅「有个 client 实例」
    "exfil": [
        r"(requests|httpx|aiohttp|httpx\.AsyncClient|urllib\.request)\s*[.(].{0,60}"
        r"\b(post|put|patch)\b",
        r"\bdata\s*=\s*(payload|dumps|json\.dumps|str\(|base64)",
        r"\bupload\b.{0,30}\b(file|data|payload|content)\b",
        r"\bs3\.upload|\bboto3.*put_object|\bgcs\.upload",
        r"\bpostmultipart|\bformdata\b",
    ],
}


def scan_repo(repo, branch):
    import recheck
    f, n, miss = recheck.cache_files(repo, branch)
    if not f:
        return []
    hits = []
    for fp, src in f.items():
        if not fp.endswith(".py"):
            continue
        low = fp.replace("\\", "/").lower()
        if re.search(r"(^|/)(tests?|examples?|mocks?|samples?|fixtures?|"
                     r"benchmarks?|docs?)(/|$)", low):
            continue
        if re.search(r"(^|/)(test_[^/]*|[^/]*_test)\.py$", low):
            continue
        if re.search(r"(^|/)(conftest|mock_[^/]*|[^/]*_mock)\.py$", low):
            continue
        L = src.splitlines()
        for cat, pats in NEW_SINKS.items():
            for pi, pat in enumerate(pats):
                rx = re.compile(pat, re.I)
                for i, line in enumerate(L, 1):
                    if line.strip().startswith("#"):
                        continue
                    m = rx.search(line)
                    if not m:
                        continue
                    hits.append({
                        "cat": cat, "pat_idx": pi,
                        "file": fp, "line": i,
                        "code": line.strip()[:150],
                        "match": m.group(0)[:40],
                    })
    return hits


def main():
    recs = J.load_recs()
    targets = sorted({v.get("_repo") for v in
                      json.load(open(os.path.join(POOL, "llm_verdict.json"),
                                   encoding="utf-8")).values()} - {None})
    print("★ 旋钮三 · 危险出口清单加长")
    print("  现有清单（论文原有）：EXEC_FUNCS %d 项 + CLIENT_FUNCS %d 项"
          % (len(A.EXEC_FUNCS), len(A.CLIENT_FUNCS)))
    print("  新增清单：%s（%d 条正则）"
          % (list(NEW_SINKS), sum(len(v) for v in NEW_SINKS.values())))
    print()
    print("%-34s %-8s %s" % ("项目", "新增命中", "分类分布"))
    print("-" * 76)

    allhits = []
    for repo in targets:
        rec = recs.get(repo)
        br = (rec.get("branch") if rec else None) or "main"
        hs = scan_repo(repo, br)
        if not hs:
            continue
        c = Counter(h["cat"] for h in hs)
        print("%-34s %-8d %s" % (repo.split("/")[-1][:34], len(hs),
                                 dict(c)))
        for h in hs:
            h["_repo"] = repo
            h["_branch"] = br
        allhits.extend(hs)

    json.dump(allhits, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    print()
    print("=" * 76)
    print("新增命中合计：%d 处" % len(allhits))
    print("=" * 76)
    c = Counter(h["cat"] for h in allhits)
    for cat, n in c.most_common():
        print("  %-12s %d" % (cat, n))
    print()
    print("★ 对比：现有清单在同批项目上命中 code_exec_sink %d 处"
          % sum(v["cells"]["code_exec_sink"]["n"] for v in recs.values()))
    print("  → 新增 %d 处，相当于把出口面扩大了 %.1f%%"
          % (len(allhits),
             100.0 * len(allhits) / max(1, sum(v["cells"]["code_exec_sink"]["n"]
                                             for v in recs.values()))))
    print()
    print("★ 但这些**只是「用到了这个 API」**，不是「能泄露数据」——")
    print("  下一步要让 LLM 判：外部数据能不能到达这里、带了什么。")
    print("结果写入 %s" % OUT)


if __name__ == "__main__":
    main()