# -*- coding: utf-8 -*-
"""★★ 第二轮判定：给needs_human 的补上「它缺的那一条证据」。

★ 为什么第一轮会卡在这
-------------------
第一层判据是「多用户模型」，但 LLM 判这一层要回答三个问题：
  ① 存储层有没有 owner/scope 字段？
  ② ★ **那个字段的值是外部能指定的吗？**（← 16 处全卡在这）
  ③ 这个服务对外可达吗？

★ 第一轮我只喂了「有鉴权机制线索」和「存储层身份字段线索」，
  **没喂「这个字段的值从哪来」** ——
  于是 LLM 只能说「无法确认 scope 是否对应用户身份」。

★★ 这不是 prompt 的问题，是**证据没给够**。
   → 「needs_human」这一档的价值就在这里：
     它不是失败的判定，是**精确指出还缺哪块证据**。

★ 补什么（三样，一次性抓全）
  ① **端点参数里有没有 owner/scope/tenant 类的可指定参数**
     ← 这是「外部能不能指定身份」的决定性证据
  ② **存储层的隔离字段 + 它有没有被用进查询条件**
  ③ **服务监听地址**（0.0.0.0=对外可达 / 127.0.0.1=仅本地）
"""
import io
import json
import os
import re
import sys
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm_client as LC
import llm_judge as J

POOL = J.POOL
OUT = os.path.join(POOL, "llm_verdict2.json")

# ★★ 第二轮的 prompt：只在第一轮基础上「加一段证据说明」，
#    判据本身不改 —— 这样两轮的结论差异只来自证据，不来自尺度。
RUBRIC2 = J.RUBRIC + """

---

★★ 补充证据说明（这是你上一轮说「无法确认」的那些点，现在给你）

【★ 端点参数里有没有「身份标识」类的可指定参数】
下面列出的是**从 HTTP 请求参数里能拿到的所有身份类参数**。
★ 判断要点：**如果这个参数是 str / Optional[str] 之类的普通入参，
  没有任何依赖注入或鉴权代码给它赋值 → 外部可以任意指定。**
{REQ_PARAMS}

【★ 存储层的身份字段，是否被用进查询条件】
{SSTORE_EVIDENCE}

【★ 服务监听地址】
{BIND_EVIDENCE}

★★ 因此回答第一层时，请明确区分这两种情况：
  · 身份字段存在 **且** 值只能由服务端产生（从 token/session 解出来）
    → 缺的是鉴权 → 无鉴权 = 真越权
  · 身份字段存在 **但** 值来自请求参数（外部可任意指定）
    → 仍然是真越权（越权成立：能冒充任何人）
  · 身份字段**不存在**（只有一个全局字典/一张表）
    → 没有多用户模型 → 不是漏洞
"""
BIND_RE = re.compile(r"(0\.0\.0\.0|127\.0\.0\.1|localhost|host\s*=|bind\s*=|"
                     r"uvicorn\.run|app\.run\(|serve\()", re.I)
# ★ 端点签名里的身份类参数
ID_PARAM = re.compile(
    r"\b(owner_id|owner|user_id|uid|tenant_id|tenant|scope_id|scope|"
    r"account_id|principal|workspace_id|org_id|team_id|"
    r"creator_id|created_by|author|belong\w*)\b", re.I)


def collect_extra(repo, rec, fmap, ev):
    """抓第一轮没给的三样证据。"""
    #① 端点签名里的身份类参数
    req_params = []
    src = fmap.get(ev["file"], "")
    try:
        import ast
        tree = ast.parse(src)
    except Exception:
        tree = None
    if tree:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
               and node.lineno == ev["line"]:
                args = node.args
                names = [a.arg for a in args.args + args.kwonlyargs]
                hit = [n for n in names if ID_PARAM.search(n)]
                defaults = []
                for a in args.args:
                    if a.arg in hit:
                        d = ast.unparse(a) if hasattr(ast, "unparse") else ""
                        defaults.append(d[:90])
                req_params = hit
                if defaults:
                    req_params = ["%s   ← 默认值形态：%s" % (h, " | ".join(defaults[:2]))
                                  for h in hit]
                break

    # ② 存储层：身份字段 + 有没有被用进 filter
    store_ev = []
    for fp, c in fmap.items():
        if not fp.endswith(".py") or "/tests/" in fp:
            continue
        L = c.splitlines()
        for i, l in enumerate(L, 1):
            if re.search(r"\.filter\(\s*\w*\.(owner_id|user_id|tenant_id|scope_id)", l) \
               or re.search(r"(owner_id|user_id|tenant_id)\s*==\s*", l):
                store_ev.append("%s:%d  %s" % (fp.split("/")[-1][:34], i,
                                               l.strip()[:92]))
        if len(store_ev) >= 6:
            break

    # ③ 监听地址
    bind = []
    for fp, c in fmap.items():
        if not fp.endswith(".py") or "/tests/" in fp:
            continue
        L = c.splitlines()
        for i, l in enumerate(L, 1):
            if BIND_RE.search(l):
                bind.append("%s:%d  %s" % (fp.split("/")[-1][:34], i,
                                           l.strip()[:92]))
        if len(bind) >= 4:
            break

    return req_params, store_ev[:8], bind[:4]


def main():
    import recheck
    vd = json.load(open(os.path.join(POOL, "llm_verdict.json"), encoding="utf-8"))
    nh = {k: v for k, v in vd.items() if v.get("verdict") == "needs_human"}
    print("待第二轮判定：%d 处" % len(nh))
    done = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}
    recs = J.load_recs()

    by_repo = defaultdict(list)
    for k, v in nh.items():
        by_repo[v.get("_repo")].append((k, v))

    cost0 = LC.USAGE.cny
    for repo, items in by_repo.items():
        rec = recs.get(repo)
        if not rec:
            continue
        br = rec.get("branch") or "main"
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            continue
        ctx = J.fmt_ctx(repo, J.build_context(rec, fmap))

        for k, v in items:
            if k in done:
                continue
            ev = {"file": v["_file"], "line": v["_line"],
                  "route": v.get("_route", "")}
            rp, se, bd = collect_extra(repo, rec, fmap, ev)

            extra = ("\n\n--- 第二轮补充 ---\n"
                     "【★ 端点参数里有没有身份标识类的可指定参数】\n"
                     + ("\n".join("  " + x for x in rp) if rp else "  （该端点签名里没有这类参数）")
                     + "\n\n【★ 存储层身份字段是否被用进查询条件】\n"
                     + ("\n".join("  " + x for x in se) if se else "  （没找到把身份字段用进 filter/== 的地方 → 身份字段可能没真正隔离数据）")
                     + "\n\n【★ 服务监听地址】\n"
                     + ("\n".join("  " + x for x in bd) if bd else "  （没找到显式监听配置）"))

            body = J.get_body(fmap, ev, maxlines=80)
            user = (ctx + "\n\n" + J.fmt_item(ev, body)
                    + "\n\n请按三层判据判断这个命中是不是真漏洞。")
            try:
                r = LC.ask_json(RUBRIC2, user + extra, tag="llm_verdict2",
                                max_tokens=3600)
            except Exception as e:
                print("  ★ %s 失败：%s" % (repo.split("/")[-1][:20], str(e)[:50]))
                continue
            r["_repo"] = repo
            r["_file"] = ev["file"]
            r["_line"] = ev["line"]
            r["_route"] = ev.get("route", "")
            r["_prev_verdict"] = "needs_human"
            r["_id_params"] = rp
            done[k] = r
            json.dump(done, open(OUT, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
            print("  %-26s %-12s → %-12s conf=%.2f  %s"
                  % (repo.split("/")[-1][:26], "needs_human",
                     r.get("verdict"), r.get("confidence", 0),
                     (r.get("one_line") or "")[:50]))

    print("\n第二轮完成 %d 处，花费 %.4f 元" % (len(done), LC.USAGE.cny - cost0))
    from collections import Counter
    print("分布：" + json.dumps(dict(Counter(
        v.get("verdict") for v in done.values())), ensure_ascii=False))


if __name__ == "__main__":
    main()