# -*- coding: utf-8 -*-
"""★核实第 2 步自动化：先查「这个项目有没有多用户模型」。

★ 为什么必须单独做成一步（而不是逐条读）
------------------------------------------------
核实 rhesis 得出的结论：**判据报的27 处技术上都是真的**，
但它们**不是漏洞** —— 因为存储层是进程内全局字典、没有 owner 隔离，
  整个服务根本没有「别人的数据」这个概念。

→ 「检出 ≠ 有洞」中间的这一层，判据完全没有覆盖。
  而且它**不需要逐条读**，可以**先按项目批量过一遍**：
  一个项目有没有多用户模型，是**项目级**的属性，不是端点级的。

★ 三档判定（只能这么分，判据给不出）
────────────────────────────────────
  multi   有多用户模型 → 「无鉴权」**可能是越权**，要往下读三层
  single  明确单用户（本地 demo / CLI / 库型）→ **不是漏洞**
  unknown 看不出来 → 必须人工读

判别信号（按可信度排序，越靠前越硬）：
  ① 存储层条目里有没有 owner/user_id/tenant/principal 字段
  ② 有没有 user 表 / 用户体系 / 登录注册端点
  ③ 项目自述里出现 multi-tenant / multi-user / SaaS
  ④ ★ 反向信号：docstring 说 local demo / CLI / library / single-user
"""
import io
import json
import os
import re
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recheck

HERE = os.path.dirname(os.path.abspath(__file__))
POOL = os.path.normpath(os.path.join(HERE, "..", "data", "target_pool"))

# ============ 三档判定规则 ============
# ★ 规则写在数据里而不是代码里 —— 这样能一眼看出"哪条判的"，
#   也方便以后调（调规则不该改逻辑）。

MULTI_STORE = re.compile(
    r"\b(owner_id|user_id|tenant_id|principal_id|account_id|"
    r"created_by|belong|workspace_id|org_id|team_id)\b", re.I)

MULTI_AUTH = re.compile(
    r"(create_user|register_user|login|signin|sign_in|authenticate|"
    r"current_user|get_current_user|UserAccount|class\s+User\b|"
    r"user_table|users\s*=\s*\[|USER_STORE|user_repo)", re.I)

MULTI_CLAIM = re.compile(
    r"(multi[- ]tenant|multi[- ]user|saas|per[- ]user|"
    r"team[- ]based|organization|workspace)", re.I)

SINGLE_CLAIM = re.compile(
    r"(local demo|for a local|local[- ]only|single[- ]user|"
    r"cli tool|command[- ]line|this is a library|"
    r"in-process|not.*intended for (production|multi))", re.I)

# ★ 目录形态：这些目录里的代码是「独立小应用」，天然单用户
DEMO_DIR = re.compile(
    r"(^|/)(examples?|demos?|samples?|quickstart|tutorials?|"
    r"mock[^/]*|developer-tools)(/|$)", re.I)


def load_repo_data():
    """读已跑好的批次，不重新扫。"""
    out = {}
    p = os.path.join(POOL, "rc_v7_partial.jsonl")
    if not os.path.exists(p):
        print("找不到 %s —— 先跑 recheck.py" % p)
        sys.exit(2)
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        out[d["repo"]] = d
    return out


def classify(repo, rec):
    """判一个项目是 multi / single / unknown。返回 (档位, 依据列表)。"""
    ua = rec["cells"]["unauth_endpoint"]["n"]
    if ua == 0:
        return "skip", ["判据报 0，没有命中可核实"]

    ev = rec.get("evidence", {}).get("unauth_endpoint", []) or []
    files = sorted(set(e["file"] for e in ev))

    # 只在命中文件所在的「应用」里找信号，避免被依赖库里的 user_id 干扰
    sig_multi_store, sig_multi_auth, sig_multi_claim, sig_single = [], [], [], []

    for fp in files:
        if DEMO_DIR.search(fp):
            continue
        try:
            files_map, _n, _m = recheck.cache_files(repo, _branch_of(rec))
        except Exception:
            files_map = {}
            break
        src = files_map.get(fp)
        if not src:
            continue
        for m in MULTI_STORE.finditer(src):
            sig_multi_store.append("%s:%d %s" % (fp.split("/")[-1],
                                                  src[:m.start()].count("\n") + 1,
                                                  m.group(0)))
        for m in MULTI_AUTH.finditer(src):
            sig_multi_auth.append("%s:%d %s" % (fp.split("/")[-1],
                                                src[:m.start()].count("\n") + 1,
                                                m.group(0)[:30]))
        for m in MULTI_CLAIM.finditer(src):
            sig_multi_claim.append("%s:%d %s" % (fp.split("/")[-1],
                                                  src[:m.start()].count("\n") + 1,
                                                  m.group(0)[:30]))
        for m in SINGLE_CLAIM.finditer(src):
            sig_single.append("%s:%d %s" % (fp.split("/")[-1],
                                            src[:m.start()].count("\n") + 1,
                                            m.group(0)[:30]))
        break# 第一次拿到 map 就够了

    # 判定：反向信号优先（作者自己说了是 demo，最硬）
    if sig_single:
        return "single", ["作者明示：%s" % s for s in sig_single[:3]]
    if sig_multi_store and (sig_multi_auth or sig_multi_claim):
        return "multi", ["存储层有身份字段：%s" % s for s in sig_multi_store[:3]] + \
                       ["有用户体系：%s" % s for s in (sig_multi_auth[:2] or sig_multi_claim[:2])]
    if sig_multi_auth:
        return "multi?", ["有用户体系但存储层没看到 owner 字段：%s" % s
                          for s in sig_multi_auth[:3]]
    if sig_multi_store:
        return "multi?", ["存储层有身份字段但没找到用户体系：%s" % s
                          for s in sig_multi_store[:3]]
    return "unknown", ["三类信号都没找到，必须人工读"]


BRANCH_CACHE = {}


def _branch_of(rec):
    """recheck.py 用GitHub 的 default_branch，它已把branch 记在记录里。"""
    b = rec.get("branch")
    if b:
        BRANCH_CACHE[rec["repo"]] = b
        return b
    # ★ 不要退回 "main" —— 10-07 踩过：SampleSDK 在 master，
    #   用 main 查返回 py=0，被误判成「没缓存」。
    return "master"


def main():
    recs = load_repo_data()
    print("=" * 76)
    print("★ 多用户模型预筛 —— 核实前必过的一步")
    print("=" * 76)
    print()
    print("%-34s %-5s %-9s %s" % ("项目", "ua", "档位", "依据"))
    print("-" * 76)

    rows = []
    for repo in sorted(recs):
        ua = recs[repo]["cells"]["unauth_endpoint"]["n"]
        if ua == 0:
            continue
        # 把 branch 传进 cache_files
        _branch_of(recs[repo])
        tier, why = classify(repo, recs[repo])
        rows.append((tier, repo, ua, recs[repo]["cells"]["inconsistent_auth"]["n"], why))

    order = {"multi": 0, "multi?": 1, "unknown": 2, "single": 3, "skip": 4}
    rows.sort(key=lambda r: (order.get(r[0], 9), -r[2]))

    for tier, repo, ua, ia, why in rows:
        print("%-34s %-5d %-9s %s" % (repo, ua, tier, why[0][:60]))
        for w in why[1:3]:
            print("%-49s %s" % ("", w[:70]))

    print()
    from collections import Counter
    c = Counter(r[0] for r in rows)
    print("-" * 76)
    print("档位分布：%s" % dict(c))
    print()
    print("★ 怎么读这个结果：")
    print("  multi   → 真可能越权，★优先核实（要往下读三层）")
    print("  multi?  → 有信号但不确定，人工看一眼存储层")
    print("  unknown → 信号都没有，★必须人工读（最耗时）")
    print("  single  → 作者明示是 demo/CLI/库型，★★ 不是漏洞，可跳过")


if __name__ == "__main__":
    main()