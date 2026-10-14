# -*- coding: utf-8 -*-
"""★★ LLM 判定层 —— 把「判据报的可疑点」变成「有依据的结论」。

═══ 为什么这是基础架构的核心 ═══
这是我搭的流水线**后半截**。前半截（静态判据）已经够用了，
后半截原来全靠人工读源码—— 慢（20-40 分钟/项目）、不可复现、尺度不统一。

★ 这个模块做成「旋钮无关」：
  输入 = 一批静态命中 + 判据说明
  输出 = 每处的结构化结论（verdict + 三层证据 + 置信度）
  → **五个旋钮都能复用同一套判定流程**，只是喂进去的证据不同。

═══ 三条不可省的设计 ═══
① **判据写进 prompt，不让它自由心证**
   —— 尺度必须固定，否则「检出率」每次都不一样，论文没法写。

② **LLM 只做分类，不做最终结论**
   —— 低置信度的升级给人。三层判据里有一层「拿不准」就必须交给人。

③ **★ 用我人工核实的 4 个项目做标准答案（gold set）**
   —— 有 4 个项目的定论（rhesis/astra/Clawith/agentUniverse 全部 not_vuln，
     各自理由不同）。**每次改 prompt 都要在这 4 个上跑一遍**，
     看结论有没有翻转。翻转了就是 prompt 改坏了。
   ★ 这是整个模块最重要的一条 —— 没有 gold set，
     「调 prompt」就是拍脑袋，改好改坏 unknowable。
"""
import io
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import llm_client as LC

ROOT = LC.ROOT
POOL = os.path.join(ROOT, "data", "target_pool")

# ══════════════════════════════════════════════════════════════════
# 判据说明 ——★ 共享前缀，放最前面才能命中 prompt cache（省 50 倍钱）
# ══════════════════════════════════════════════════════════════════
RUBRIC = """你是一个 Agent 项目漏洞判定的复核员。

我会给你：某个 Python 项目的源码片段（静态扫描已报「该对外端点无鉴权」），
以及这个项目的鉴权机制概况。你的任务是判断这个命中**是不是真漏洞**。

判定必须严格按下面三层来，逐层回答，不要跳层：

第一层 · 多用户模型：这个服务有没有多用户概念？
  判据：看数据存储层 —— 如果所有数据存在**一个全局字典**里、
  键只有业务 id（如 conversation_id）而**没有 owner / user_id / tenant 字段**，
  那就**没有多用户模型**，缺少的不是鉴权而是多用户设计 → 不是漏洞。
  只有存储层有身份隔离字段时，「无鉴权」才可能是越权。

第二层 · 本来就该公开：这个端点是不是设计上就该无鉴权？
  判据：以下类型**本来就该公开**，报它们不是漏洞：
  - 密码重置 / 登录 / 注册 / 验证码 / 邮箱验证
  - 健康检查 / 版本号 / 状态查询
  - 公开行情、公开文档、注册链接、referral 链��
  - 框架/ SDK 自身开放的接口（使用者自己注册能力的那种）
  反之，**管理后台 / 配置修改 / 凭据读取 / 数据删除**这类接口，
  无鉴权就是严重问题。

第三层 · 能触达什么：这个端点无鉴权后能干什么？
  从轻到重：读公开信息 < 读他人数据 < 写/ 改他人数据 < 执行任意代码
  报「执行任意代码」需要额外证据：service_id 之类的参数能映射到
  文件路径 / 模块路径，或能调用未被限制的外部接口。
  **只读配置文件驱动的动态加载不算漏洞。**

输出 JSON，字段固定：
{
  "multiusers": "yes|no|unclear",
  "multiusers_evidence": "一句话，引用你看到的具体代码（如 self._briefs: dict[str, TripBrief]）",
  "by_design_public": "yes|no|unclear",
  "by_design_evidence": "一句话",
  "reach": "public|read_own|read_other|write|exec",
  "reach_evidence": "一句话",
  "verdict": "vuln|not_vuln|needs_human",
  "confidence": 0.0 到 1.0 之间的小数,
  "one_line": "一句话结论"
}

判定尺度（务必照此，不要放宽也不要收紧）：
- verdict = vuln      需同时满足：有「多用户模型」+ 不是「设计上该公开」+ 能触达他人数据或执行
- verdict = not_vuln   满足任一：无多用户模型 / 设计上该公开 / 只能读公开信息
- verdict = needs_human 你**无法从给出的代码判断**，或第三层拿不准
- confidence 必须如实给。信息不足时给低分，**不要为了给答案而虚报高分**。"""


# ══════════════════════════════════════════════════════════════════
# gold set —— ★ 我人工核实过的 4 个项目，用来验 prompt 没被改坏
# ══════════════════════════════════════════════════════════════════
# ★ 记的是「整项目的定论」，不是单点的。
#   因为一个项目的 6 处可能有的判 vuln 有的判 not_vuln，
#   拿单点当标准太严（LLM 判得比我保守也算「翻转」）。
GOLD = {
    "rhesis-ai/rhesis": {
        "verdict": "not_vuln",
        "why": "StateStore 全局字典、键只有 conversation_id、无 owner 字段；"
               "docstring 明写 enough for a local demo",
    },
    "0xethanq/astra-quant-agent": {
        "verdict": "not_vuln",
        "why": "命中的 7 处全是行情/版本号/注册链接，docstring 明写「公开只读、"
               "不需要任何鉴权」",
    },
    "dataelement/Clawith": {
        "verdict": "not_vuln",
        "why": "密码重置链路做了防用户枚举（统一响应）、用一次性 token；"
               "真正的改密码接口 /me/password 挂了 Depends",
    },
    "agentuniverse-ai/agentUniverse": {
        "verdict": "not_vuln",
        "why": "service_id 只能取已 register 的服务（生产代码零注册）；"
               "importlib 动态加载的输入来自配置文件、是私有方法零调用点",
    },
}


# ══════════════════════════════════════════════════════════════════
# 证据抽取
# ══════════════════════════════════════════════════════════════════
AUTH_KW = ("Depends", "middleware", "api_key", "APIKeyHeader", "HTTPBearer",
           "OAuth2", "Authorization", "current_user", "user_id",
           "require_", "get_current_", "verify_", "APIRouter(", "FastAPI(")
# ★ 这三个正则独立于判据 —— 否则判据漏的写法这里也会漏，
#   那就变成「用判据验判据」，验证等于没做。
GUARD = re.compile(
    r"\b(require|verify|validate|ensure|check)_[\w]+\s*\(|"
    r"\b(get_current_user|get_current_admin|require_auth|verify_token|"
    r"check_permission|require_admin|is_authenticated)\s*\(", re.I)
STORE = re.compile(r"(owner_id|user_id|tenant_id|principal_id|account_id|"
                   r"created_by|belongs_to|workspace_id)", re.I)


def collect_branch(recs):
    return {r: d.get("branch") for r, d in recs.items()}


def load_recs(batch="rc_v8_partial.jsonl"):
    p = os.path.join(POOL, batch)
    out = {}
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        out[d["repo"]] = d
    return out


def build_context(rec, fmap):
    """把一个项目的鉴权概况 + 存储层证据抽出来，作为共享上下文。"""
    auth, store, dyn = [], [], []
    for fp, src in fmap.items():
        if not fp.endswith(".py"):
            continue
        low = fp.lower()
        if "/tests/" in low or "/mock" in low or "/examples/" in low:
            continue
        for i, l in enumerate(src.splitlines(), 1):
            s = l.strip()
            if not s or len(s) > 160:
                continue
            if any(k in s for k in AUTH_KW) and len(auth) < 22:
                auth.append("%s:%d  %s" % (fp.split("/")[-1][:34], i, s))
            if STORE.search(s) and len(store) < 12:
                store.append("%s:%d  %s" % (fp.split("/")[-1][:34], i, s))
            if re.search(r"(importlib|__import__|eval\(|exec\(|subprocess|os\.system)", s) \
               and len(dyn) < 8:
                dyn.append("%s:%d  %s" % (fp.split("/")[-1][:34], i, s))

    return {
        "auth": auth, "store": store, "danger": dyn,
        "total_py": sum(1 for p in fmap if p.endswith(".py")),
    }


def fmt_ctx(repo, ctx):
    L = ["【项目】%s（py 文件 %d 个）" % (repo, ctx["total_py"]), "",
         "【鉴权机制线索】"]
    L += ["  " + x for x in ctx["auth"]] or ["  （无）"]
    L += ["", "【存储层的身份字段线索 —— 判断有没有多用户模型看这里】"]
    L += ["  " + x for x in ctx["store"]] or ["  （无 —— 这通常意味着没有 owner 隔离）"]
    L += ["", "【动态加载 / 执行命令线索 —— 判断有没有 RCE 面看这里】"]
    L += ["  " + x for x in ctx["danger"]] or ["  （无）"]
    return "\n".join(L)


def fmt_item(ev, body):
    return ("【被报的端点】%s:%d\n  路由：%s\n  函数签名：%s\n\n"
            "【该函数完整源码】\n%s"
            % (ev["file"], ev["line"], ev.get("route", "-"),
               (ev.get("text") or "")[:160],
               "\n".join("  " + l for l in body)))


def get_body(fmap, ev, maxlines=70):
    """取该函数完整源码。★ 用 AST 精确定位，不用行号猜。"""
    import ast
    src = fmap.get(ev["file"])
    if not src:
        return []
    try:
        tree = ast.parse(src)
    except Exception:
        return []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
           and n.lineno == ev["line"]:
            try:
                return ast.unparse(n).splitlines()[:maxlines]
            except Exception:
                return []
    return []


# ══════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════
def judge_batch(repos, batch="rc_v8_partial.jsonl", out_tag="llm_verdict",
                limit_per_repo=None, dry=False):
    import recheck
    recs = load_recs(batch)
    OUT = os.path.join(POOL, out_tag + ".json")
    done = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}

    total = 0
    for repo in repos:
        rec = recs.get(repo)
        if not rec:
            print("  ! %s 不在批次里" % repo)
            continue
        evs = rec.get("evidence", {}).get("unauth_endpoint", []) or []
        if not evs:
            print("  - %s 判据报 0，跳过" % repo)
            continue
        if limit_per_repo:
            evs = evs[:limit_per_repo]

        br = rec.get("branch") or "main"
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            print("  ! %s 取不到源码（branch=%s）" % (repo, br))
            continue
        ctx = build_context(rec, fmap)
        ctx_txt = fmt_ctx(repo, ctx)

        for ev in evs:
            key = "%s|%s|%d" % (repo, ev["file"], ev["line"])
            if key in done:
                continue
            total += 1
            if dry:
                print("  [dry] %s" % key)
                continue
            body = get_body(fmap, ev)
            user = (ctx_txt + "\n\n" + fmt_item(ev, body)
                    + "\n\n请按三层判据判断这个命中是不是真漏洞。")
            try:
                r = LC.ask_json(RUBRIC, user, tag=out_tag, max_tokens=1200)
            except Exception as e:
                print("  ★ %s LLM 失败：%s" % (key[:50], e))
                continue
            r["_repo"] = repo
            r["_file"] = ev["file"]
            r["_line"] = ev["line"]
            r["_route"] = ev.get("route", "")
            r["_branch"] = br
            done[key] = r
            json.dump(done, open(OUT, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
            print("  %-30s %-12s conf=%.2f  %s"
                  % (repo.split("/")[-1][:30], r.get("verdict", "?"),
                     r.get("confidence", 0), (r.get("one_line") or "")[:46]))

    print("\n" + "=" * 66)
    print("本轮新增 %d 处 → %s" % (total, OUT))
    print("累计已判 %d 处" % len(done))
    print("花费：" + LC.USAGE.report())
    c = Counter(v.get("verdict") for v in done.values())
    print("分布：" + json.dumps(dict(c), ensure_ascii=False))
    return done


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                                  errors="replace")
    args = sys.argv[1:]
    dry = "--dry" in args
    repos = [a for a in args if not a.startswith("--")]
    if not repos:
        repos = sorted(GOLD.keys())
    judge_batch(repos, limit_per_repo=None if dry else 3, dry=dry)