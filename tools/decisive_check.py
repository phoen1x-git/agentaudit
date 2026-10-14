# -*- coding: utf-8 -*-
"""★ 决定性实验（批量版）：对所有报非 0 的项目，逐个端点验证判据说得对不对。

★ 为什么必须做这一步
------------------
判据报「端点无鉴权」，但它只是一套**语法信号**（依赖注入、装饰器、
守卫调用）。语法能证明「有鉴权」，**不能证明「没鉴权」**——
因为鉴权可以藏在判据认不出的写法里（守卫对象、自定义中间件、
Header 注入…）。

决定性实验：
    对每个报出来的 (file, line) → 用 AST 取那个 def 的**函数体**
    → 看有没有守卫调用。
       有 → ★ 判据假阳性（判据没认出来）
       无 → 判据说的对，但要人工确认「这个服务有没有多用户模型」

★ 这个实验比逐条读源码快几个数量级，而且**只用 AST 不猜内容**。
  它把「358 处」变成「n 处真+ m 处假」的分类，
  让人工核实只需要看那 n 处。
"""
import ast
import io
import json
import os
import re
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import recheck

POOL = os.path.normpath(os.path.join(HERE, "..", "data", "target_pool"))

# ★ 守卫调用的名字形态。与 ast_criteria 的 _GUARD_NAME 保持一致但更宽 ——
#   这里是为了**独立验证**，不能复用判据自己的词表，
#   否则判据漏的写法这里也会漏（那就白验了）。
GUARD = re.compile(
    r"\b(require|verify|validate|ensure|check|assert)_[\w]+\s*\("
    r"|\b(current_user|get_current_user|get_current_admin|"
    r"get_principal|get_identity|require_auth|verify_token|"
    r"check_permission|require_admin|is_authenticated|verify_password)\s*\("
    r"|\b(authenticate|authorize)\s*\(", re.I)

# ★ 判据认出的鉴权形态（用来区分「判据该认的」和「判据该认但没认」）
DEPENDS = re.compile(r"\bDepends\s*\(")
DECOR_AUTH = re.compile(
    r"@(app|router|bp|blueprint)\.(get|post|put|delete|patch|route)\s*\([^)]*"
    r"(dependencies\s*=|Depends\s*\()", re.I)


def load_batch(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        out[d["repo"]] = d
    return out


def check_project(repo, rec):
    """返回 (真无守卫的命中列表, 有守卫的命中列表, 跳过的)。"""
    ua = rec["cells"]["unauth_endpoint"]["n"]
    if ua == 0:
        return [], [], []
    ev = rec.get("evidence", {}).get("unauth_endpoint", []) or []
    if not ev:
        return [], [], list(range(len(ev)))

    # ★★ 用rec 里记的 branch（= GitHub default_branch），
    #   不要退回 "main" —— 10-07 踩过：SampleSDK 在 master，
    #   用 main 查返回 py=0，会被误判成「这项目没缓存」。
    br = rec.get("branch") or "main"
    try:
        fmap, _n, _m = recheck.cache_files(repo, br)
    except Exception as e:
        return [], [], ["取缓存失败:%s" % e]

    # 建 (file, lineno) -> (函数名, 函数体文本)
    parsed = {}
    for fp, src in fmap.items():
        if not fp.endswith(".py"):
            continue
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                try:
                    un = ast.unparse(node)
                except Exception:
                    continue
                # ★ 只取 def 行之后的部分 = 函数体
                body = un.split("\n", 1)[1] if "\n" in un else ""
                parsed[(fp, node.lineno)] = (node.name, body)

    real, fake, skip = [], [], []
    for e in ev:
        key = (e["file"], e["line"])
        if key not in parsed:
            skip.append((e, "没定位到函数"))
            continue
        name, body = parsed[key]
        # ★ def 行里可能带 Depends（形如 def x(request, u=Depends(get_user))）
        sig = ast.unparse(getattr(e, "_sig", "")) if False else ""
        if GUARD.search(body):
            fake.append((e, name, body))
        else:
            real.append((e, name, body))
    return real, fake, skip


def main():
    batch = os.path.join(POOL, "rc_v8_partial.jsonl")
    if not os.path.exists(batch):
        print("找不到 %s" % batch)
        return 2
    recs = load_batch(batch)

    print("=" * 78)
    print("★ 决定性实验：判据报的每一处，函数体里到底有没有守卫调用")
    print("=" * 78)
    print()
    print("%-34s %-6s %-8s %-8s %s"
          % ("项目", "判据", "★真无", "假阳性", "备注"))
    print("-" * 78)

    tot_real = tot_fake = 0
    summary = {}
    for repo in sorted(recs):
        ua = recs[repo]["cells"]["unauth_endpoint"]["n"]
        if ua == 0:
            continue
        real, fake, skip = check_project(repo, recs[repo])
        tot_real += len(real)
        tot_fake += len(fake)
        note = ""
        if skip:
            note = "%d 处没定位到" % len(skip)
        print("%-34s %-6d %-8d %-8d %s"
              % (repo, ua, len(real), len(fake), note))
        summary[repo] = {
            "ua": ua, "real_no_guard": len(real),
            "fake_has_guard": len(fake), "skipped": len(skip),
        }
        # 详细列出「真无守卫」的（这些是人工核实要看的第一批）
        if real:
            print("      ★真无守卫的 %d 处:" % len(real))
            for e, name, body in real[:8]:
                print("         %-40s %-28s %s"
                      % (e["file"].split("/")[-1][:40],
                         e.get("route", "-")[:28],
                         e.get("text", "")[:40]))
            if len(real) > 8:
                print("         ...还有 %d 处" % (len(real) - 8))

    print()
    print("=" * 78)
    print("合计：判据报 %d 处 → 真无守卫 %d 处 + 判据假阳性 %d 处"
          % (tot_real + tot_fake, tot_real, tot_fake))
    print("=" * 78)
    print()
    print("★ 怎么读这个结果：")
    print("  「真无守卫」= 判据说的对，要人工确认「这个服务有没有多用户模型」")
    print("  「假阳性」  = ★ 判据没认出来 → 要么补判据，要么记为已知盲区")
    print()
    print("★ 假阳性率高的项目，说明它的鉴权写法比较特殊，值得单独看。")

    out = os.path.join(POOL, "decisive_check.json")
    json.dump(summary, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\n结果: %s" % out)


if __name__ == "__main__":
    sys.exit(main())