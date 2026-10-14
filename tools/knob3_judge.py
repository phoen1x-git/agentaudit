# -*- coding: utf-8 -*-
"""★★★ 旋钮三 · Step 2：判「新增出口命中里，哪些是**真能外泄数据**的」。

★ 为什么这一步才是旋钮三的真正难点
────────────────────────────────────
Step 1 扫出 2973 处「用到了写库/发邮件/发消息/外部传输」的代码。
★ 但**「用了这个 API」≠「能泄露数据」**：
  · ORM 的正常 `session.add(obj)` / `commit()` —— 不是漏洞
  · `requests.get(url)` 拉公开网页 —— 不是外泄
  · `send_email(to=..., body=通知内容)` 固定内容 —— 不是泄露

★ 旋钮三的真正命题不是「清单加长」，
   而是「**加长了之后怎么不把噪声也一起加进来**」。
   → 这正是论文那个「手工清单可以加长」背后的隐藏代价。

★★ 所以判定必须回答三件事：
  ① 这个出口的**数据来自哪里**（外部输入 / 用户会话 / 内部常量）
  ② 有没有**脱敏或白名单**（只发固定通知 = 不可控）
  ③ ★ 外部输入能不能**到达**这里（数据流是否闭合）
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
import recheck

POOL = J.POOL
OUT = os.path.join(POOL, "knob3_verdict.json")

RUBRIC_K3 = """你是一个 Agent 项目「数据外泄面」的判定员。

背景：我们在扩展一张「危险操作出口清单」。原论文只盯三类
（执行命令 / 读写文件 / 把字符串当代码执行），
现在加了四类：写数据库、发邮件、发消息、对外传输。

★ 你的任务**不是**判断「这段代码有没有漏洞」，而是判断：
**「这个出口点，是不是一条『外部数据可以流出去』的通道」**

判定三件事：
① ★ 数据来源：这个出口发送/写入的内容，来自哪里？
   - 外部输入（用户消息、上传的文件、抓取的网页、模型输出）→ 可控
   - 内部常量 / 固定通知模板 → 不可控
   - 配置里的常量（如 API key、目标 URL）→ ★ 要看是读还是写
② ★ 有没有约束：目标地址是写死的还是外部可指定的？
   - 写死（如只发到 ops@公司.com）→ 不可控
   - 外部可指定（URL/token/收件人来自请求参数）→ ★ 可控
③ ★ 数据流是否闭合：从外部输入到这里的路径通吗？

★★ 最常见的误判（务必避开）：
  · ORM 的正常 `session.add(obj)` + `commit()` → **不是外泄通道**
  · `requests.get(url)` 拉公开网页 → **不是外泄**（是拉取）
  · `send_email(body="服务重启通知")` 固定内容 → 不可控
  · ★ 但 `send_email(body=user_input)` → ★ **可控外泄**

输出 JSON：
{
  "data_source": "external_input|internal_constant|config|user_session|unclear",
  "data_source_evidence": "一句话，引用你看到的变量名",
  "target_controllable": "yes|no|unclear",
  "target_evidence": "一句话",
  "flow_closed": "yes|no|unclear",
  "verdict": "real_channel|not_channel|needs_human",
  "severity": "none|low|medium|high",
  "confidence": 0.0-1.0,
  "evidence": "一句话，引用具体代码",
  "one_line": "一句话结论"
}

判定尺度：
- real_channel  数据来源是外部输入 **且** 目标外部可指定 **且** 数据流通
- not_channel  至少一条不成立（数据是内部常量 / 目标写死 / 拉取而非发送）
- needs_human  代码片段不足以判断（如看不到数据从哪来）
★ severity 参考：high=任意数据可控且目标任意；medium=目标写死但数据外部可控；
low=数据外部可控但目标固定；none=不是通道
★ 信息不足就给 needs_human 并如实降低 confidence，
  **不要为了给答案而把三条都答 yes**。"""


def build_ctx(repo, fmap):
    """项目级鉴权概况（与判定层同款，复用）。"""
    auth, store = [], []
    for fp, src in fmap.items():
        if not fp.endswith(".py"):
            continue
        low = fp.replace("\\", "/").lower()
        if re.search(r"(^|/)(tests?|examples?|mocks?)(/|$)", low):
            continue
        for i, l in enumerate(src.splitlines(), 1):
            s = l.strip()
            if not s or len(s) > 160:
                continue
            if re.search(r"(Depends|middleware|api_key|Authorization|current_user)",
                         s) and len(auth) < 14:
                auth.append("%s:%d  %s" % (fp.split("/")[-1][:30], i, s[:88]))
            if re.search(r"(owner_id|user_id|tenant_id)", s) and len(store) < 8:
                store.append("%s:%d  %s" % (fp.split("/")[-1][:30], i, s[:88]))
    return {"auth": auth, "store": store}


def main():
    per_repo = int(os.environ.get("K3_PER_REPO", "6"))
    hits_all = json.load(open(os.path.join(POOL, "knob3_sinks.json"),
                              encoding="utf-8"))
    # ★ 先按项目分组，每个项目取分数最高的若干个
    by_repo = {}
    for h in hits_all:
        by_repo.setdefault(h["_repo"], []).append(h)

    done = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    print("待判 %d 处（每项目取前 %d）" % (len(hits_all), per_repo))
    print()
    print("=" * 74)
    print("★ Step 2：LLM 判「这是不是一条真实的外泄通道」")
    print("=" * 74)

    cost0 = LC.USAGE.cny
    for repo in sorted(by_repo):
        hs = by_repo[repo]
        # ★ 分类取样：每类最多 2 个，保证四类都被判到
        picked = []
        bycat = {}
        for h in hs:
            bycat.setdefault(h["cat"], []).append(h)
        for cat, lst in sorted(bycat.items()):
            picked.extend(lst[:max(1, per_repo // 4 + 1)])
        picked = picked[:per_repo + 4]

        br = hs[0]["_branch"]
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            continue
        ctx = build_ctx(repo, fmap)
        lines = ["【项目】%s" % repo, "",
                 "【鉴权机制线索】"] + ["  " + x for x in (ctx["auth"] or ["（无）"])]
        ctx_txt = "\n".join(lines)

        for h in picked:
            key = "%s|%s|%d|%s" % (repo, h["file"], h["line"], h["cat"])
            if key in done:
                continue
            # ★ 给它所在函数的上下文（单行看不出数据来源）
            src = fmap.get(h["file"], "")
            body = J.get_body(fmap, h, maxlines=60) if hasattr(J, "get_body") else []
            if not body:
                body = _grep_ctx(src, h["line"], 30)
            user = ("%s\n\n【被判定的出口点】%s:%d（分类：%s）\n"
                    "  命中片段：%s\n\n【所在函数的完整源码】\n%s\n\n"
                    "请判断：这是不是一条「外部数据可以流出去」的通道？"
                    % (ctx_txt, h["file"], h["line"], h["cat"], h["code"],
                       "\n".join("  " + b for b in body)))
            try:
                r = LC.ask_json(RUBRIC_K3, user, tag="knob3", max_tokens=3600)
            except Exception as e:
                print("  ★ %s 失败：%s" % (repo.split("/")[-1][:20], str(e)[:44]))
                continue
            r["_repo"] = repo
            r["_file"] = h["file"]
            r["_line"] = h["line"]
            r["_cat"] = h["cat"]
            r["_code"] = h["code"]
            done[key] = r
            json.dump(done, open(OUT, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
            print("  %-24s %-11s %-13s %-7s conf=%.2f %s"
                  % (repo.split("/")[-1][:24], h["cat"], r.get("verdict"),
                     r.get("severity"), r.get("confidence", 0),
                     (r.get("one_line") or "")[:44]))

    print()
    print("判定 %d 处，花费 %.4f 元" % (len(done), LC.USAGE.cny - cost0))
    print("verdict:   %s" % dict(Counter(v.get("verdict")
                                        for v in done.values())))
    print("severity:  %s" % dict(Counter(v.get("severity")
                                       for v in done.values())))
    print("★ 对照：原清单（code_exec_sink）在同批项目上命中 759 处")


def _grep_ctx(src, line, pad=25):
    """没有 AST 就退回按行取窗口。"""
    L = (src or "").splitlines()
    a = max(0, line - pad)
    b = min(len(L), line + pad)
    return ["%5d| %s" % (i + 1, L[i][:110]) for i in range(a, b)]


if __name__ == "__main__":
    main()