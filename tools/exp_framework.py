# -*- coding: utf-8 -*-
"""★★★ 旋钮对比实验框架 —— 论文形式的「基线 → 逐旋钮叠加 → 拿数据」

═══ 我之前做错在哪 ═══
每个旋钮单独跑，没有基线。结果是「旋钮三精确率 3.1%」「旋钮四 26%」，
★ **这些数字互相之间不能比**，因为分母/判定标准/样本量全不一样。

═══ 论文要的是什么 ═══
`docs/01_方向与决策.md` 定的是「改一个旋钮 → 跑对比 → 拿数据」。
★ 所以必须有**基线**（=论文原样），然后每个旋钮是**在基线之上的增量**。

═══ 统一口径 ═══
所有实验都用**同一套判定标准**（两层），同一批30 个项目，同一份抽样规则：

  第一层：污点成立吗？   （外部数据 → 危险操作，数据流闭合）
  第二层：★ 职责内吗？   （这个危险操作是该功能的职责吗）★ 旋钮三的教训

  最终结论 = 两层都真才��� `real`

═══ 成本控制 ═══
全量判定 4000+ 处按 0.0085 元/处要 34 元，余额只有 9.89 元。
→ ★ **必须分层抽样 + 给置信区间**，而不是硬跑全量。
  统计上这更严谨（能报置信区间比报单点更可信）。
"""
import io
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast
import llm_client as LC
import llm_judge as J
import recheck

POOL = J.POOL
EXPERIMENTS = os.path.join(POOL, "experiments.json")

# ══════════════════════════════════════════════════════════════════
# ★★ 统一判定 prompt —— 基线和所有旋钮共用，★ 只有「证据段」不同
# ══════════════════════════════════════════════════════════════════
RUBRIC_UNIFIED = """你是一个 Agent 项目污点漏洞的统一判定器。

★ 所有实验（基线/ 各旋钮）都用你这套标准，**不要改尺度**。

给定：① 项目概况（含鉴权机制线索）② 一个可疑点③ 它所在函数的完整源码。

═══ 第一层：污点成立吗？ ═══
A1 外部数据：有没有真的外部数据进来？
   ★ 是「路径配置项」（file_path="/etc/x"）不算
   ★ 「内部常量 / 枚举 / 固定通知模板」不算
B1 危险操作：外部数据有没有流到这些？
   · 执行命令 / 把字符串当代码 / 写删文件 / 发外部请求
   · ★★ **进了 LLM 的 prompt 也算**（那是间接的指令/代码执行面）
C1 数据流：从入口到危险操作通吗？

═══ 第二层：★ 职责内吗？ ═══
D1 ★ 这个「危险操作」是**该组件/该端点的职责本身**吗？
   ★ Webhook/invoker 类 →它的职责就是往配置的 endpoint 发数据 → **职责内**
   ★ 通知类 → 职责就是发给接收人 → **职责内**
   ★ 文件上传端点 → 职责就是把上传的文件存起来 → **职责内**
   ★ 反之：查询接口里写了文件、聊天接口里执行命令 → **不是职责内**

★★ 最容易错的两点：
  ① 把「有防护的实现」判成洞→ ★ 看到 `relative_to()` / 白名单 /
     `basename()` / `secure_filename` / `isalnum` 这类防护，要判not
  ② 把「职责内」判成洞 → ★ 先问「这个组件存在的理由是不是这件事」

═══ 输出 ═══
{
  "external_data": "yes|no|unclear",
  "danger_reached": "yes|no|unclear",
  "flow_closed": "yes|no|unclear",
  "protection_present": "yes|no",        ★ 有防护措施吗
  "protection_evidence": "一句话，引用具体防护代码",
  "is_duty": "yes|no|unclear",
  "duty_evidence": "一句话，引用类名/函数名/docstring",
  "verdict": "real|not_real|needs_human",
  "severity": "none|low|medium|high",
  "confidence": 0.0-1.0,
  "evidence": "一句话，引用具体代码",
  "one_line": "一句话结论"
}

判定尺度（★ 严格照此）：
- real        第一层三条全 yes（或 protection_present=no）**且** is_duty=no
- not_real    第一层任一不成立，**或** is_duty=yes，**或** protection_present=yes
- needs_human 代码不足以下判断

★ severity 只在 verdict=real 时给：
  high=任意数据可控 + 目标任意 / 执行命令
  medium=写文件、数据外部可控
  low=目标固定、或只影响本用户
★ 信息不足给 needs_human 并**如实降低 confidence**，
  **不要为了给答案而把各条都答 yes**。"""


def wilson(k, n, z=1.96):
    """★ Wilson 区间 —— 小样本下比「k/n」稳得多。

    ★ 为什么用它：n=20 时「5/20=25%」的 95% 区间其实是 11%~45%，
      直接报 25% 会让人以为很准。论文里报区间才诚实。
    """
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    lo = (c - m) / d
    hi = (c + m) / d
    return (p, max(0.0, lo), min(1.0, hi))


def fpr(sig_text):
    """★ 误报率 = 非真 / 总（论文口径：报出来的东西里有多少不是真的）"""
    n = len(sig_text)
    if n == 0:
        return (0, 0.0, 0.0, 0.0)
    good = sum(1 for t in sig_text if t == "real")
    nh = sum(1 for t in sig_text if t == "needs_human")
    p, lo, hi = wilson(good, n)
    return (n, good, p, hi - lo)


# ══════════════════════════════════════════════════════════════════
# ★★ 统一的候选生成：★ 从 evidence 里读，★ 不重新扫
# ══════════════════════════════════════════════════════════════════
def load_evidence(cells=("code_exec_sink", "injection_surface",
                         "dangerous_cooccurrence")):
    """基线候选 = 现有判据报的三类（= 论文原样的三类出口）。"""
    out = defaultdict(list)
    for line in open(os.path.join(POOL, "rc_v8_partial.jsonl"), encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        for c in cells:
            for e in (d.get("evidence", {}).get(c) or []):
                e = dict(e)
                e["_repo"] = d["repo"]
                e["_branch"] = d.get("branch") or "main"
                e["_cell"] = c
                out[d["repo"]].append(e)
    return out


def stratified_sample(items, per_stratum=2, seed=13):
    """★ 分层抽样：★ 每类（cell）× 每项目 取 N 个。

    ★ 为什么要分层：简单随机抽样会被大项目主导
      （trinity 一个项目占 764 处），抽样结果会全是 trinity。
    ★ 固定 seed → 可复现（论文要求）。
    """
    import random
    rng = random.Random(seed)
    by = defaultdict(list)
    for it in items:
        by[it["_cell"]].append(it)
    picked = []
    for cell in sorted(by):
        lst = sorted(by[cell], key=lambda x: (x["_repo"], x["file"], x["line"]))
        rng.shuffle(lst)
        # ★ 每项目最多 per_stratum 个，避免一个项目占满
        seen = Counter()
        for it in lst:
            if seen[it["_repo"]] >= per_stratum:
                continue
            seen[it["_repo"]] += 1
            picked.append(it)
            if len(seen) == 0:
                break
            if sum(seen.values()) >= per_stratum * 12:
                break
    return picked


def _func_containing(src, line):
    """★ 找「包含这一行的函数」——★ 不是「定义在这一行的函数」。

    踩过的坑：判据报的 `line` 是**危险操作那一行**（如 `subprocess.run(...)`
    在第 60 行），而那个函数**定义在第 58 行**。
    → 按 `n.lineno == line` 找，**永远找不到**；
      `judge_one` 于是返回 None，**整批判定变成 0 处而日志看不出异常**。
    ★ 这跟 docs/49 那个「外部给的行号不能直接用」是同一类，
      但方向相反：那次是行号对不上，这次是★ **行号对得上，
      但它指的不是定义位置**。

    → 正确做法：取**范围包含该行**的最小函数。
    """
    try:
        tree = ast.parse(src)
    except Exception:
        return []
    best = None
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        a = n.lineno
        b = getattr(n, "end_lineno", a) or a
        if a <= line <= b:
            # ★ 取最小的那个（嵌套函数里选最内层）
            if best is None or (b - a) < (best[1] - best[0]):
                best = (a, b, n)
    if best:
        a, b, n = best
        try:
            out = ast.unparse(n).splitlines()[:70]
        except Exception:
            out = []
        if out:
            # ★ 把定义行标出来，让人知道这是「整个函数」
            out.insert(0, "【%s：%d-%d 行】" % (n.name, a, b))
            return out
    # 找不到函数就退回按行取窗口（模块级代码）
    L = src.splitlines()
    a0 = max(0, line - 30)
    return ["%5d| %s" % (i + 1, L[i][:110])
            for i in range(a0, min(len(L), line + 30))]


def judge_one(ev, extra_ctx="", tag="exp"):
    """判一处，返回 verdict 字符串。"""
    repo = ev["_repo"]
    br = ev.get("_branch") or "main"
    fmap, _n, _m = recheck.cache_files(repo, br)
    if not fmap:
        alt = "master" if br == "main" else "main"
        fmap, _n, _m = recheck.cache_files(repo, alt)
    if not fmap:
        return None
    body = []
    src = fmap.get(ev["file"], "")
    if src:
        body = _func_containing(src, ev["line"])
    if not body:
        return None

    user = ("【项目】%s\n【可疑点】%s:%d（判据类别 %s）\n  路由：%s\n  代码：%s\n\n"
            "【函数完整源码】\n%s\n%s\n"
            "请按统一口径判定。"
            % (repo, ev["file"], ev["line"], ev.get("_cell", "?"),
               ev.get("route", "-"), (ev.get("text") or "")[:150],
               "\n".join("  " + x[:112] for x in body), extra_ctx))
    try:
        r = LC.ask_json(RUBRIC_UNIFIED, user, tag=tag, max_tokens=3600)
    except Exception:
        return None
    r["_repo"] = repo
    r["_file"] = ev["file"]
    r["_line"] = ev["line"]
    r["_cell"] = ev.get("_cell")
    return r


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="baseline")
    ap.add_argument("--per-stratum", type=int, default=2)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    print("=" * 74)
    print("★ 旋钮对比实验 · %s" % a.name)
    print("=" * 74)
    base = load_evidence()
    tot = sum(len(v) for v in base.values())
    print("基线候选（论文原三类出口）：%d 处，%d 个项目"
          % (tot, len(base)))

    picked = []
    for repo in sorted(base):
        picked.extend(stratified_sample(base[repo], a.per_stratum))
    if a.limit:
        picked = picked[:a.limit]
    print("分层抽样（每项目每类 %d 个）：%d 处" % (a.per_stratum, len(picked)))
    print()

    out = os.path.join(POOL, "exp_%s.json" % a.name)
    done = json.load(open(out, encoding="utf-8")) if os.path.exists(out) else {}
    verdicts = []
    cost0 = LC.USAGE.cny
    for i, ev in enumerate(picked, 1):
        key = "%s|%s|%d" % (ev["_repo"], ev["file"], ev["line"])
        if key in done:
            verdicts.append(done[key].get("verdict"))
            continue
        r = judge_one(ev, tag="exp_" + a.name)
        if not r:
            continue
        done[key] = r
        json.dump(done, open(out, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        verdicts.append(r.get("verdict"))
        if i % 10 == 0 or i == len(picked):
            print("  [%d/%d] %s" % (i, len(picked),
                                     dict(Counter(verdicts))))

    print()
    n, good, p, half = fpr([v or "?" for v in verdicts])
    print("=" * 74)
    print("★ %s 实验结果" % a.name)
    print("=" * 74)
    print("  判定%d 处：%s" % (len(verdicts), dict(Counter(verdicts))))
    print("  ★ 精确率 =real / 判定数 = %d / %d = **%.1f%%**（±%.1f%%）"
          % (good, n, p * 100, half * 100))
    sev = Counter(r.get("severity") for k, r in done.items()
                  if r.get("verdict") == "real")
    print("  ★ real 的严重性分布：%s" % dict(sev))
    print("  花费 %.4f 元" % (LC.USAGE.cny - cost0))

    ex = {}
    if os.path.exists(EXPERIMENTS):
        ex = json.load(open(EXPERIMENTS, encoding="utf-8"))
    ex[a.name] = {"n_judged": n, "n_real": good, "precision": p,
                  "ci_half": half, "verdicts": dict(Counter(verdicts)),
                  "severity": dict(sev), "n_candidates": tot,
                  "n_sampled": len(picked)}
    json.dump(ex, open(EXPERIMENTS, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("  累计实验记录 → %s" % EXPERIMENTS)


if __name__ == "__main__":
    main()