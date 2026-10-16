#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
目标筛选器（target screener）
============================

目的：把「选样」从经验判断变成一条可自动跑的规则，产出一份候选目标清单。

为什么需要它
------------
实测 5 个目标，4 个已修或已归档 —— 头部项目的洞早被挖完了。
所以选样必须额外排除两个维度：
    1) 头部（已被深度审计）
    2) 已在管安全（有 SECURITY.md / 有安全公告 → 洞会被更快修掉）

★ 本脚本的规则全部可自动判定，不需要人工看仓库。
  规则设计刻意分三层，因为 GitHub 未认证只有 60 次/小时的核心额度：

    Layer 0  拉候选池        search API，每个 query 1 次请求
    Layer 1  硬性过滤        search 结果自带字段，0 次额外请求
    Layer 2  能否装上        PyPI API，无额度限制
    Layer 3  深查            GitHub core API，昂贵，只对入围者跑

用法
----
    python target_screener.py fetch      # 拉候选池（Layer 0）
    python target_screener.py screen     # 跑筛选（Layer 1+2，便宜）
    python target_screener.py deep       # 深查入围者（Layer 3，昂贵）
    python target_screener.py report     # 出候选清单 Markdown
    python target_screener.py selftest   # ★ 先跑这个：验规则本身对不对

★ 断点续跑：所有 API 结果落盘缓存到 _cache/，重跑不重复花额度。
★ 限流：未认证 60 次/小时。脚本会读 rate_limit 自动退避；设 GH_TOKEN 可提到 5000。
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
OUT = os.path.join(PROJ, "data", "target_pool")
CACHE = os.path.join(OUT, "_cache")

# 候选池状态文件
POOL_FILE = os.path.join(OUT, "pool.json")
SCREEN_FILE = os.path.join(OUT, "screened.json")
DEEP_FILE = os.path.join(OUT, "deep.json")

TOKEN = os.environ.get("GH_TOKEN", "").strip()

# ★ 从文件读token（比环境变量方便：不用每次手动设）
#   读取顺序：$GH_TOKEN → $GH_TOKEN_FILE → 项目约定的 secrets 文件
#   ★ 只读不打印，且不写入任何日志/报告。
_TOKEN_FILE_ENV = os.environ.get("GH_TOKEN_FILE", "").strip()
if not TOKEN and _TOKEN_FILE_ENV:
    try:
        with open(_TOKEN_FILE_ENV, "r", encoding="utf-8") as _f:
            TOKEN = _f.read().strip()
    except Exception:
        TOKEN = ""

if not TOKEN:
    # 约定位置（不进版本库、不写进报告）
    for _cand in (
        os.path.expanduser("~/.github_token"),
        os.path.expanduser("~/Desktop/api/github.txt"),
    ):
        try:
            if os.path.exists(_cand):
                with open(_cand, "r", encoding="utf-8") as _f:
                    TOKEN = _f.read().strip()
                break
        except Exception:
            pass
UA = "target-screener/1.0"


# ---------------------------------------------------------------- 基础设施

def ensure_dirs():
    os.makedirs(CACHE, exist_ok=True)


def _cache_path(key):
    safe = re.sub(r"[^A-Za-z_.-]", "_", key)[:180]
    return os.path.join(CACHE, safe + ".json")


def http_json(url, use_cache=True, cache_key=None):
    """带磁盘缓存的 GET。缓存命中不花任何额度。"""
    ensure_dirs()
    cp = _cache_path(cache_key or url)
    if use_cache and os.path.exists(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN

    req = urllib.request.Request(url, headers=headers)
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode("utf-8"))
            with open(cp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            return data
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:200]
            except Exception:
                pass
            last_err = "HTTP %s %s" % (e.code, body)
            # 额度用尽：退避后重试一次
            if e.code in (403, 429):
                reset = _reset_seconds(e)
                if reset is not None and reset < 3700 and attempt < 2:
                    print("    [限流] 等待 %d 秒 ..." % (reset + 5), flush=True)
                    time.sleep(reset + 5)
                    continue
            return {"_error": last_err, "_status": e.code}
        except Exception as e:
            last_err = "%s: %s" % (type(e).__name__, e)
            time.sleep(2)
    return {"_error": last_err}


def _reset_seconds(e):
    try:
        hdr = e.headers.get("x-ratelimit-reset")
        if hdr:
            return max(0, int(hdr) - int(time.time()))
    except Exception:
        pass
    return None


def rate_limit():
    d = http_json("https://api.github.com/rate_limit")
    c = (d.get("resources") or {}).get("core") or {}
    return {
        "limit": c.get("limit"),
        "remaining": c.get("remaining"),
        "reset_in": _fmt_reset(c.get("reset")),
    }


def _fmt_reset(ts):
    if not ts:
        return None
    return "%d 分钟" % max(0, round((ts - time.time()) / 60.0))


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_since(s):
    if not s:
        return None
    try:
        t = datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None
    return (datetime.now(timezone.utc) - t).days


# ---------------------------------------------------------------- already-covered list

# Repositories that should be excluded because they have already been examined -- by a paper,
# by someone else, or by you. This is what makes "not yet examined" mean something.
#
# It is a file rather than a constant here, and the file ships empty. A list of real
# repositories says more about whoever wrote the tool than about the tool, and a list that is
# half anonymised says even more: the placeholders mark the ones somebody thought worth hiding.
#
#   cp core/config/known_targets.example.yml core/config/known_targets.yml
KNOWN_FILE = Path(os.environ.get("AF_KNOWN_TARGETS")
                  or os.path.join(PROJ, "core", "config", "known_targets.yml"))


def load_known() -> tuple[set, set]:
    """(already covered, already tried). Both empty when there is no config file."""
    if not KNOWN_FILE.exists():
        return set(), set()
    doc = yaml.safe_load(KNOWN_FILE.read_text(encoding="utf-8")) or {}
    to_lower = lambda xs: {str(x).strip().lower() for x in (xs or []) if str(x).strip()}
    return to_lower(doc.get("already_covered")), to_lower(doc.get("already_tried"))


# ---------------------------------------------------------------- 规则

# ★ 主题/描述里的信号词。用集合投票，不靠单一名字匹配。
#   （教训：按名字匹配 = 换个名字就瞎，栽过四次）
#
# ★★ 词表要宽。规则的目的是**召回** Agent 项目，不是精确分类。
#   #   第一版 LLM 维度只认 "llm/gpt/openai"，于是把描述写 "biomedical AI agent" 的
#   项目、以及写 "multi-agent poster" 的项目全误杀了 —— 现代项目的描述早就不
#   一定写 LLM，写的是 AI / model / 生成式，
AGENT_TOPIC_WORDS = {
    "agent", "agents", "ai-agent", "ai-agents", "agentic", "autonomous-agent",
    "agentops", "llm-agent", "llm-agents", "multi-agent", "multi-agent-system",
    "multi-agent-systems", "agent-framework", "agentframeworks", "agent-skills",
    "agent-skill", "agent-orchestration", "agent-gateway", "agent-platform",
    "autonomous-agents", "coding-agent", "computer-use-agent", "ai-agents",
}
LLM_TOPIC_WORDS = {
    "llm", "llms", "gpt", "openai", "anthropic", "claude", "gemini", "llama",
    "rag", "langchain", "llmops", "prompt", "chatgpt", "generative-ai",
    "ai", "artificial-intelligence", "multimodal", "vlm", "foundation-model",
    "llm-agent", "llmops", "a2a", "mcp", "agentic-ai", "ai4science",
}
DESC_AGENT_RE = re.compile(r"\b(agent|agentic|autonomous)\b", re.I)
DESC_LLM_RE = re.compile(
    r"\b(llm|large language model|gpt|openai|claude|gemini|llama|chatbot|"
    r"rag|retrieval[- ]augmented|prompt|\bai\b|\bml\b|machine learning|"
    r"模型|智能体|生成式|多模态)\b", re.I)

# ★ 「像 Agent 框架」的信号：要有工具/行动能力，只有 LLM 不够
ACTION_WORDS = re.compile(
    r"\b(tool|tools|function call|plugin|plugins|skill|skills|workflow|"
    r"mcp|action|execute|executor|toolkit|automat)", re.I)

# star 区间：太高=已被审计，太低=可能不维护
STAR_MIN = 200
STAR_MAX = 5000
# 半年内有提交（交接档案建议）
MAX_DAYS_SINCE_PUSH = 183


def looks_like_agent(name, desc, topics):
    """判断是否「像 LLM Agent 项目」。

    ★ 返回 (verdict, score, reasons)。
      verdict 只有三个值，好判真假：
        'yes'   —— 多个独立信号同时命中
        'maybe' —— 信号弱，可能是相关但不同类
        'no'    —— 基本不是 Agent 项目
    ★ 返回的是启发式判断，不是硬规则 —— 报告里会标明这一点。
    """
    topics_l = {str(t).lower() for t in (topics or [])}
    desc = desc or ""

    t_agent = len(topics_l & AGENT_TOPIC_WORDS)
    t_llm = len(topics_l & LLM_TOPIC_WORDS)
    d_agent = 1 if DESC_AGENT_RE.search(desc) else 0
    d_llm = 1 if DESC_LLM_RE.search(desc) else 0
    has_action = 1 if ACTION_WORDS.search(desc + " " + name) else 0

    score = 2 * t_agent + 1 * t_llm + 2 * d_agent + 1 * d_llm + 2 * has_action

    reasons = []
    if t_agent:
        reasons.append("topics含agent词%d个" % t_agent)
    if t_llm:
        reasons.append("topics含llm词%d个" % t_llm)
    if d_agent:
        reasons.append("描述含agent")
    if d_llm:
        reasons.append("描述含llm/模型名")
    if has_action:
        reasons.append("有工具/行动类信号")

    # ★★★ 三个维度，每个维度的信号来源都是「topics 或 描述」（两个都算）。
    #   第一版只让描述提供 LLM 信号，于是漏掉了一批真项目：多智能体海报生成、
#   GUI agent、自主数据标注的 agent 框架 —— 它们都是 agent，只是描述里不写 "LLM"。
    #   → 结论：现代 Agent 项目的自我描述在 topics 上比在 description 上更完整。
    #     只看一个字段就等于"按名字匹配"的另一种形式。
    dim_hit = (t_agent > 0) or (d_agent > 0)
    llm_hit = (t_llm > 0) or (d_llm > 0)
    # 行动维度：topics 里有 agent 相关的功能词也算（gui-agent/phone-use-agent
    # 这类本身就是行动能力的声明）
    act_hit = has_action > 0 or bool(
        topics_l & {"gui-agent", "gui-agents", "computer-use", "phone-use-agent",
                    "coding-agent", "autonomous-agents", "agent-skills",
                    "agent-skill", "task-automation", "agent-based-framework",
                    "agent-oriented-programming", "agent-gateway",
                    "agent-orchestration", "agent-platform"})

    if dim_hit and llm_hit and act_hit:
        verdict = "yes"
    elif dim_hit and (llm_hit or act_hit):
        # ★ maybe 的门槛是「有 agent 属性 + 至少另一个维度有信号」。
        #   候选池本身就是 topic:agent 检索来的，所以"是不是 LLM 项目"在这里
        #   几乎是恒真的 —— 把它当硬门槛只会误杀：
        #   #   一批真 agent 项目卡在 no 上：多智能体海报生成、GUI agent、数据标注
        #   agent 框架。改成"不排斥"而非"必须命中"。
        #   → 真正该排掉的是**没有 agent 属性**的推理服务器，它们 dim_hit=False，
        #     落在 no 上，规则仍然对。
        verdict = "maybe"
    else:
        verdict = "no"

    return verdict, score, reasons


def screen_item(it):
    """对单个候选跑 Layer 1 硬性过滤。返回 (通过?, 原因列表)。

    ★ 只用 search 结果自带字段 —— 0 次额外 API 请求。
    """
    full = (it.get("full_name") or "").lower()
    reasons = []

    # 1) AgentFuzz测过 / 已实测过（★ 新旧名都认，避免改名后漏排除）
    if is_paper_target(full):
        return False, ["AgentFuzz已测过或本项目已实测过"]

    # 2) 归档 —— 已归档的仓库不会有新洞可挖
    if it.get("archived"):
        reasons.append("仓库已归档")

    # 3) fork —— 上游不认 fork 的漏洞，且 fork 的修复不回传
    if it.get("fork"):
        reasons.append("是fork")

    # 4) 语言 —— 流水线是 Python 静态分析，非 Python 直接出局
    if (it.get("language") or "").lower() != "python":
        reasons.append("非Python(%s)" % (it.get("language") or "?"))

    # 5) 活跃度
    d = days_since(it.get("pushed_at"))
    if d is None:
        reasons.append("拿不到pushed_at")
    elif d > MAX_DAYS_SINCE_PUSH:
        reasons.append("已停更%d天" % d)

    # 6) star 区间
    st = it.get("stargazers_count") or 0
    if st > STAR_MAX:
        reasons.append("star过高%d(已被审计)" % st)
    elif st < STAR_MIN:
        reasons.append("star过低%d" % st)

    # 7) 是否像 Agent 项目
    verdict, score, rs = looks_like_agent(
        it.get("name"), it.get("description"), it.get("topics"))
    if verdict == "no":
        reasons.append("不像Agent项目")
    else:
        reasons.append("agent信号[%s]%s" % (verdict, "+".join(rs) or "-"))

    return (len(reasons) == 0 or
            (reasons and reasons[0].startswith("agent信号"))), reasons


# ---------------------------------------------------------------- Layer 2: PyPI

def pypi_info(pkg):
    """查 PyPI。★ PyPI 无速率限制，这条规则基本免费。"""
    if not pkg:
        return None
    d = http_json("https://pypi.org/pypi/%s/json" % pkg)
    if "_error" in d or "info" not in d:
        return {"found": False}
    info = d["info"]
    ver = info.get("version")
    rels = d.get("releases") or {}
    up = None
    if ver and rels.get(ver):
        up = (rels[ver][0].get("upload_time") or "")[:10]
    return {
        "found": True,
        "name": info.get("name"),
        "version": ver,
        "requires_python": info.get("requires_python"),
        "uploaded": up,
        "summary": (info.get("summary") or "")[:120],
        "home_page": info.get("home_page") or "",
    }


def guess_pkg_name(full_name):
    """从 repo 名猜 PyPI 包名。猜不到就返回 None —— 不瞎猜。"""
    name = full_name.split("/")[-1].lower()
    name = name.replace("_", "-")
    # 明显的非发布名
    if name in ("agent", "agents", "theia", "examples", "docs", "docs-cn"):
        return None
    return name


# ---------------------------------------------------------------- Layer 3: 深查

def deep_one(full_name, branch):
    """★ 昂贵：每个候选 **1 次** core 请求（树），一次拿全部规则。

    查四件用 search 拿不到、但决定「值不值得挖」的事：
      1) 有没有 SECURITY.md      —— 有人在管安全（反直觉规则）
      2) 有没有 server/api 层    —— 攻击面（交接档案的教训6）
      3) 有没有工具/插件注册机制 —— 二阶污点能不能落地
      4) 代码规模               —— 太小不可信

    ★★ 第一版这里有两个错，都是同一个病根：
       (a) 用 contents/SECURITY.md 判断，返回的是 dict 不是 list，
           于是 `isinstance(sec, list)` 恒为 False → **所有目标都报「无 SECURITY.md」**。
           one project 实测根目录就有 SECURITY.md。
       (b) 只看**顶层**目录名找 server/api 层，而真实项目里 server 代码
           常在 examples/ 或子包内（如 one project 的 examples/.../http_server_fastapi.py），
           于是 has_server_dir 全线 False → **等于没看**。
       教训：「该出现的东西出现了」≠「它出现在该在的地方、并且被看见」。
       现在改成：只用一次树请求，所有规则都从**完整路径列表**里按内容找。
    """
    out = {"full_name": full_name, "branch": branch}

    tree = http_json(
        "https://api.github.com/repos/%s/git/trees/%s?recursive=1" % (full_name, branch))
    entries = tree.get("tree") or []
    if not entries:
        msg = tree.get("_error") or tree.get("message") or "空树"
        if tree.get("message") == "Not Found":
            msg = "树请求404：默认分支名可能不是 %s（应从 pool 里取 default_branch）" % branch
        out["tree_error"] = msg
        return out

    out["tree_ok"] = True
    out["truncated"] = bool(tree.get("truncated"))
    paths = [e.get("path") or "" for e in entries]
    low = [p.lower() for p in paths]
    py = [p for p in low if p.endswith(".py")]

    # 1) SECURITY.md：全树按文件名找（含 .github/security.md）
    sec_paths = [p for p in low if os.path.basename(p) == "security.md"]
    out["security_md"] = bool(sec_paths)
    out["security_md_paths"] = sec_paths[:5]

    # 2) server/api 层：★ 按路径**内容**找，不限层级、不限顶层
    #    ★★ 但"名字里带 api/server"不等于服务端。三类必须排掉（实测踩到的）：
    #       - 第三方 vendor 代码（比如随包带进来的 _vendor/ 下面的实现）
    #       - CLI 入口（api/cli/commands/*.py 这类）
    #       - 调用别人的 API 的客户端（nodes/tools/ 下面那些只是转发请求的）
    #    → 规则收紧为：**有明确服务端职责信号**才算攻击面。
    srv_real = []
    for p in low:
        if not p.endswith((".py", ".ts", ".js")):
            continue
        # 排掉：vendor/第三方、测试、示例文档
        if re.search(r"(^|/)(\.venv|venv|site-packages|node_modules|_vendor|vendor|"
                     r"third_party|thirdparty|tests?|testing|examples?|samples?|"
                     r"docs?|demos?|migrations?)/", p):
            continue
        # 排掉：CLI 入口（argparse/click 那一套）
        if re.search(r"(^|/)(cli|cmd|command|commands|scripts?|bin|tools?)/", p) and \
           re.search(r"(cli|commands?|__main__|main)\.py$", p):
            continue
        is_server = bool(re.search(
            r"(^|/)(server|servers|webapp|backend|apis?|routes?|routing|"
            r"endpoints?|controllers?|handlers?|a2a)(/|\.|_)", p))
        # 或者：文件名像服务端入口，且不在客户端工具目录里
        looks_srv = bool(re.search(
            r"\b(server|app|web|api|fastapi|starlette|flask|django|asgi|wsgi|"
            r"http)\.(py|ts|js)$", p))
        client_call = bool(re.search(
            r"(api_call|http_api|apiclient|api_client|_client|client\.|"
            r"openrouter|webhook)", p))
        if is_server or (looks_srv and not client_call):
            srv_real.append(p)
    out["has_server_dir"] = len(srv_real) > 0
    out["server_files"] = srv_real[:8]
    out["server_files_total"] = len(srv_real)
    # ★ 顶层真的有 server/ 目录（更强的信号）
    out["has_toplevel_server"] = any(
        re.match(r"^(server|servers|api|backend|webapp)/", p) for p in low)

    # 3) 工具/插件机制：★ 也不能只看目录名。
    #    某项目的 nodes/tools/ 里全是"调用工具的节点配置"，不是攻击面；
    #    真正有意义的是**工具的注册/实现**（LLM 能调的那些）。
    #    信号：文件名像工具实现，或目录里有注册表/base/factory。
    tool_real = []
    for p in low:
        if not p.endswith((".py", ".ts", ".js")):
            continue
        if re.search(r"(^|/)(\.venv|venv|site-packages|node_modules|_vendor|vendor|"
                     r"third_party|tests?|testing|examples?|samples?|docs?|demos?)/", p):
            continue
        in_tool_dir = re.search(r"(^|/)(tools?|plugins?|skills?|functions?|toolkit)(/|\.|_)", p)
        # 注册/基类/工厂 → 这就是 LLM 能调的能力面
        is_registry = bool(re.search(
            r"\b(registry|register|base|factory|manager|loader|provider|"
            r"catalog|builtin|available)\w*\.(py|ts|js)$", p))
        is_tool_impl = bool(re.search(r"\btool\w*\.(py|ts|js)$", p))
        if (in_tool_dir and (is_registry or is_tool_impl)) or is_tool_impl:
            tool_real.append(p)
    out["has_tool_dir"] = len(tool_real) > 0
    out["tool_files_total"] = len(tool_real)
    out["has_mcp"] = any("mcp" in p for p in low)
    out["tool_files"] = tool_real[:8]

    # 4) 规模与结构
    out["py_files"] = len(py)
    out["py_files_exclude_tests"] = sum(
        1 for p in py if not re.search(r"(^|/)(tests?|examples?|samples?)/", p))
    out["has_pyproject"] = any(p in ("pyproject.toml", "setup.py", "setup.cfg")
                               for p in low)
    out["has_tests"] = any(re.match(r"^(tests?|testing)/", p) for p in low)
    out["root_files"] = sum(1 for p in low if "/" not in p)
    out["total_entries"] = len(paths)
    # ★ 树被截断 = 大仓库，判定要保守（数据不全）
    if out["truncated"]:
        out["note"] = "树被GitHub截断，目录类规则可能漏判"
    return out


# ---------------------------------------------------------------- 命令

def load_pool():
    if os.path.exists(POOL_FILE):
        with open(POOL_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"repos": {}, "queries": [], "fetched_at": None}


# ★ 规范化名缓存：排除表里的项目会改名，按旧名匹配就会漏排除。
#   canonical 文件由 `resolve` 命令生成。
CANON_FILE = os.path.join(OUT, "canonical.json")

# GitHub 会把改名仓库 301 重定向到规范名。urllib 自动跟随，
# 所以响应体里的 full_name 就是规范名 —— 用它反查。
_CANON_MEM = {}


def canon_map():
    """读规范化名缓存：{旧小写名: 规范小写名}"""
    if _CANON_MEM:
        return _CANON_MEM
    if os.path.exists(CANON_FILE):
        try:
            with open(CANON_FILE, "r", encoding="utf-8") as f:
                _CANON_MEM.update(json.load(f))
        except Exception:
            pass
    return _CANON_MEM


def cmd_resolve(args):
    """Resolve the names in the exclusion list to their current canonical names, and cache that.

    Why it matters: repositories get renamed, and an exclusion list that holds only the old
    name stops matching exactly when it is needed most. Matching by name is only as good as
    the names being current.
    """
    covered, tried = load_known()
    names = sorted(covered | tried)
    cm = canon_map()
    print("解析 %d 个仓库的规范名...\n" % len(names))
    changed = []
    for i, n in enumerate(names, 1):
        d = http_json("https://api.github.com/repos/%s" % n)
        real = None
        if isinstance(d, dict) and d.get("full_name"):
            real = d["full_name"]
        elif isinstance(d, dict) and d.get("message") == "Not Found":
            print("[%2d/%d] %-38s !! 404，可能已删除或转移组织" % (i, len(names), n))
        else:
            print("[%2d/%d] %-38s ?? %s" % (
                i, len(names), n, str(d.get("message") or d.get("_error"))[:50]))

        if real:
            cm[n.lower()] = real.lower()
            if real.lower() != n.lower():
                changed.append((n, real))
                print("[%2d/%d] %-38s -> %s  ★已改名" % (i, len(names), n, real))
            else:
                print("[%2d/%d] %-38s    规范名一致" % (i, len(names), n))
        time.sleep(1.0)

    _CANON_MEM.clear()
    _CANON_MEM.update(cm)
    _save(CANON_FILE, cm)
    print("\n改名/转移的：%d 个" % len(changed))
    for a, b in changed:
        print("  %s  ->  %s" % (a, b))
    print("\n-> %s" % CANON_FILE)
    if changed:
        print("\n★ 排除表已自动包含新旧两个名，不会漏排除。")
    return 0


def is_paper_target(full_lower):
    """判断是否AgentFuzz测过 / 已实测过。★ 新旧名都认。"""
    cm = canon_map()
    cand = {full_lower, cm.get(full_lower)}
    # 反向：规范名映射回来也算
    for old, new in cm.items():
        if new == full_lower:
            cand.add(old)
    cand.discard(None)
    covered, tried = load_known()
    return bool(cand & covered) or bool(cand & tried)


def cmd_fetch(args):
    """Layer 0：多 query 拉候选池。search API 10 次/分钟，未认证。"""
    queries = [
        'topic:agent language:python stars:%d..%d pushed:>%s' % (
            STAR_MIN, STAR_MAX, _date_ago(MAX_DAYS_SINCE_PUSH)),
        'topic:ai-agent language:python stars:%d..%d pushed:>%s' % (
            STAR_MIN, STAR_MAX, _date_ago(MAX_DAYS_SINCE_PUSH)),
        'topic:llm-agent language:python stars:%d..%d pushed:>%s' % (
            STAR_MIN, STAR_MAX, _date_ago(MAX_DAYS_SINCE_PUSH)),
        'topic:agentops language:python stars:%d..%d pushed:>%s' % (
            STAR_MIN, STAR_MAX, _date_ago(MAX_DAYS_SINCE_PUSH)),
        'topic:llmops language:python stars:%d..%d pushed:>%s' % (
            STAR_MIN, STAR_MAX, _date_ago(MAX_DAYS_SINCE_PUSH)),
    ]
    if args.query:
        queries = args.query

    pool = load_pool()
    pool.setdefault("repos", {})
    for q in queries:
        url = ("https://api.github.com/search/repositories?q=%s"
               "&sort=stars&order=desc&per_page=100" % urllib.parse.quote(q))
        print("[fetch] %s" % q, flush=True)
        d = http_json(url)
        items = d.get("items") or []
        print("        total=%s  取回=%d" % (d.get("total_count"), len(items)))
        for it in items:
            fn = it.get("full_name")
            if fn:
                pool["repos"][fn.lower()] = it
        time.sleep(7)   # search 未认证 10 次/分钟，礼貌等待

    pool["queries"] = queries
    pool["fetched_at"] = now_utc()
    _save(POOL_FILE, pool)
    print("\n候选池合计 %d 个 -> %s" % (len(pool["repos"]), POOL_FILE))


def _date_ago(days):
    dt = datetime.now(timezone.utc).timestamp() - days * 86400
    return datetime.fromtimestamp(dt, timezone.utc).strftime("%Y-%m-%d")


def cmd_screen(args):
    """Layer 1+2：硬性过滤 + PyPI 可装性。便宜，全量跑。"""
    pool = load_pool()
    repos = pool.get("repos") or {}
    if not repos:
        print("候选池是空的，先跑 fetch", file=sys.stderr)
        return 1

    out = []
    for full, it in sorted(repos.items()):
        ok, reasons = screen_item(it)
        verdict, score, rs = looks_like_agent(
            it.get("name"), it.get("description"), it.get("topics"))
        rec = {
            "full_name": it.get("full_name"),
            "html_url": it.get("html_url"),
            "desc": (it.get("description") or "")[:160],
            "stars": it.get("stargazers_count"),
            "forks": it.get("forks_count"),
            "watchers": it.get("subscribers_count"),
            "open_issues": it.get("open_issues_count"),
            "pushed_at": it.get("pushed_at"),
            "days_since_push": days_since(it.get("pushed_at")),
            "size_kb": it.get("size"),
            "default_branch": it.get("default_branch"),
            "topics": it.get("topics") or [],
            "archived": it.get("archived"),
            "agent_verdict": verdict,
            "agent_score": score,
            "reasons": reasons,
            "passed_L1": ok,
        }
        if ok:
            pkg = guess_pkg_name(full)
            pi = pypi_info(pkg)
            rec["pypi_guess"] = pkg
            rec["pypi"] = pi
            rec["passed_L2"] = bool(pi and pi.get("found"))
        out.append(rec)

    _save(SCREEN_FILE, {"screened_at": now_utc(), "items": out,
                        "thresholds": {
                            "star": [STAR_MIN, STAR_MAX],
                            "max_days_since_push": MAX_DAYS_SINCE_PUSH}})

    n1 = sum(1 for r in out if r["passed_L1"])
    n2 = sum(1 for r in out if r.get("passed_L2"))
    print("候选 %d -> 过 L1 %d -> 过 L2(PyPI可装) %d" % (len(out), n1, n2))
    print("-> %s" % SCREEN_FILE)
    return 0


def cmd_deep(args):
    """Layer 3：对入围者深查。★ 花 core 额度，注意限流。"""
    if not os.path.exists(SCREEN_FILE):
        print("先跑 screen", file=sys.stderr)
        return 1
    with open(SCREEN_FILE, "r", encoding="utf-8") as f:
        scr = json.load(f)

    targets = [r for r in scr["items"] if r.get("passed_L1")]
    if args.limit:
        targets = targets[:args.limit]

    prev = {}
    if os.path.exists(DEEP_FILE):
        with open(DEEP_FILE, "r", encoding="utf-8") as f:
            prev = json.load(f).get("items") or {}
    byname = {k.lower(): v for k, v in prev.items()}

    print("额度：%s" % rate_limit())
    results = {}
    for i, t in enumerate(targets, 1):
        fn = t["full_name"]
        key = fn.lower()
        if key in byname and byname[key].get("tree_ok"):
            print("[%d/%d] %s  (已缓存)" % (i, len(targets), fn))
            results[key] = byname[key]
            continue
        print("[%d/%d] %s" % (i, len(targets), fn), flush=True)
        results[key] = deep_one(fn, t.get("default_branch") or "main")
        # 每 10 个存一次盘，中断也不丢
        if i % 10 == 0:
            _save(DEEP_FILE, {"deep_at": now_utc(), "items": results})
        time.sleep(1.0)

    _save(DEEP_FILE, {"deep_at": now_utc(), "items": results})
    print("完成 %d 个 -> %s" % (len(results), DEEP_FILE))
    return 0


def cmd_report(args):
    """出候选清单 Markdown + 控制台摘要。"""
    if not os.path.exists(SCREEN_FILE):
        print("先跑 screen", file=sys.stderr)
        return 1
    with open(SCREEN_FILE, "r", encoding="utf-8") as f:
        scr = json.load(f)
    deep = {}
    if os.path.exists(DEEP_FILE):
        with open(DEEP_FILE, "r", encoding="utf-8") as f:
            deep = {k.lower(): v for k, v in
                    (json.load(f).get("items") or {}).items()}

    rows = []
    for r in scr["items"]:
        if not r.get("passed_L1"):
            continue
        d = deep.get(r["full_name"].lower()) or {}
        score, why = score_target(r, d)
        rows.append((score, r, d, why))

    rows.sort(key=lambda x: -x[0])
    top = rows[:args.top] if args.top else rows

    lines = []
    lines.append("# 候选目标池（自动筛选产出）\n")
    lines.append("生成时间：%s\n" % scr.get("screened_at"))
    lines.append("筛选条件：star %d–%d、半年内有提交、未归档、非 fork、"
                 "非AgentFuzz已测、语言 Python、像 Agent 项目\n"
                 % (STAR_MIN, STAR_MAX))
    lines.append("## 规则约定（★ 必读，别把这些数字读成结论）\n")
    lines.append("| 显示 | 含义 |")
    lines.append("|---|---|")
    lines.append("| `—` | **没查过**（不是「没有」）|")
    lines.append("| `无` | 查过了，确实没有 |")
    lines.append("")
    lines.append("- `agent_verdict` 是**启发式**（topics/描述信号投票），"
                 "**不是硬规则**，不参与事实分。")
    lines.append("- `PyPI ✗` 只说明**猜的包名**没命中，不代表装不上 —— "
                 "包名猜错是常态。")
    lines.append("- 「未跑源码探针」的项目，**攻击面是未知的**，"
                 "分数低只反映『没数据』，不代表它差。"
                 "★ 所以**不要按分数排名直接开坑**，要先补探针数据。")
    lines.append("- 分数里的**事实分**（star/活跃度/SECURITY.md/源码信号）"
                 "与**启发式分**（像不像Agent/PyPI）是分开的，见每条的 "
                 "`score_parts`。")
    lines.append("")

    lines.append("## 入选清单\n")
    lines.append("| 分数 | 其中事实分 | 项目 | star | 最近提交 | SECURITY.md | 探针 |")
    lines.append("|---|---|---|---|---|---|---|")
    for score, r, d, why in top:
        sec = {True: "有", False: "无", None: "—"}.get(d.get("security_md"), "—")
        if d.get("ok"):
            vd = d.get("verdict") or {}
            marks = []
            if vd.get("has_http_endpoint"):
                marks.append("HTTP")
            if vd.get("has_mcp_server"):
                marks.append("MCP")
            if vd.get("has_tool_registration"):
                marks.append("工具")
            if vd.get("has_dangerous_exec"):
                marks.append("执行点")
            probe_s = "+".join(marks) if marks else "无命中"
        else:
            probe_s = "—未跑"
        sp = r.get("score_parts") or {}
        lines.append("| %d | %s | [%s](%s) | %s | %s天前 | %s | %s |" % (
            score, sp.get("facts", "—"), r["full_name"], r.get("html_url") or "",
            r.get("stars"), r.get("days_since_push"), sec, probe_s))
    lines.append("")

    lines.append("## 逐条规则依据\n")
    for score, r, d, why in top:
        lines.append("### %s（分数 %d）\n" % (r["full_name"], score))
        lines.append("- 描述：%s" % (r.get("desc") or "（无）"))
        lines.append("- Agent 信号：%s（score=%s）" % (r.get("agent_verdict"),
                                                    r.get("agent_score")))
        lines.append("- 过滤依据：%s" % "；".join(r.get("reasons") or []))
        py = r.get("pypi") or {}
        if py:
            lines.append("- PyPI：%s" % (
                "%s %s（%s 发布，requires_python=%s）" % (
                    py.get("name"), py.get("version"), py.get("uploaded"),
                    py.get("requires_python")) if py.get("found")
                else "猜的包名 %s 未命中PyPI（不等于装不上）" % r.get("pypi_guess")))
        if d:
            # ★ 只在**确实有数据**时展示，不把「没查」写成「没有」
            bits = []
            if d.get("ok"):
                vd = d.get("verdict") or {}
                cbf = d.get("counts_by_file") or {}
                bits.append("抽样覆盖 %s/%s 个 py 文件%s" % (
                    d.get("sampled_files"), d.get("total_py_files"),
                    "（★抽样非全量）" if d.get("sampled_files") else ""))
                for k, lab in [("has_http_endpoint", "对外HTTP端点"),
                               ("has_mcp_server", "MCP服务"),
                               ("has_tool_registration", "工具注册"),
                               ("has_dangerous_exec", "危险执行点"),
                               ("has_auth_surface", "认证鉴权")]:
                    bits.append("%s:%s" % (lab, "有" if vd.get(k) else "无"))
                if cbf.get("dangerous_exec"):
                    bits.append("危险执行点分布在 %d 个文件"
                                % cbf["dangerous_exec"])
                colo = vd.get("colocated_files") or []
                if colo:
                    bits.append("★★危险点与对外输入共现于 " + ", ".join(colo[:3]))
            sec = d.get("security_md")
            if sec is not None:
                bits.append("SECURITY.md:%s" % ("有" if sec else "无"))
            else:
                bits.append("SECURITY.md:未查")
            if bits:
                lines.append("- 源码/深查：" + "；".join(bits))
            lines.append("- 打分拆分：%s" % json.dumps(
                r.get("score_parts") or {}, ensure_ascii=False))
        else:
            lines.append("- 源码/深查：★**未跑**（GitHub core 额度每60 分钟重置，"
                         "本轮用完）—— 攻击面未知，不是「没有攻击面」")
        lines.append("- **打分理由**：%s\n" % "；".join(why))

    md = os.path.join(OUT, "候选目标池.md")
    with open(md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("-> %s" % md)

    print("\n===== 前 15 名（控制台速览）=====")
    for score, r, d, why in rows[:15]:
        print("%3d  %-42s star=%-6s 提交=%s天前  %s" % (
            score, r["full_name"], r.get("stars"), r.get("days_since_push"),
            "；".join(why)[:70]))
    return 0


def score_target(r, d):
    """给目标打分（0–100）。★ 每条分数都要给得出来的理由。

    ★ 打分只信**可验证的事实**：
      - star / pushed_at / 归档 → 来自 GitHub API 字段（事实）
      - SECURITY.md → 来自树里按文件名查（事实）
      - HTTP端点 / 工具注册 / 危险执行点 → 来自源码探针（事实）
      - 「像不像 Agent」 → 启发式，单独标注，不混进事实分
    """
    score = 0
    why = []
    facts = 0          # 事实分上限
    soft = 0           # 启发式分

    # ---- 事实类（满分 75）
    # 中腰部最优：太低不可信，太高被审计
    st = r.get("stars") or 0
    if 300 <= st <= 2000:
        score += 25; facts += 25
        why.append("star处于中腰部(%d)，审计压力小" % st)
    elif 200 <= st <= 3000:
        score += 15; facts += 15
        why.append("star适中(%d)" % st)
    else:
        why.append("star偏离中腰部(%d)，减分" % st)

    # 近期活跃
    dd = r.get("days_since_push")
    if dd is not None:
        if dd <= 30:
            score += 20; facts += 20
            why.append("%d天前有提交，很活跃" % dd)
        elif dd <= 90:
            score += 12; facts += 12
            why.append("%d天前有提交" % dd)
        else:
            why.append("%d天前有提交，偏冷，减分" % dd)

    # ★ 反直觉规则：没有 SECURITY.md = 没人管安全 = 洞不会被快速修掉
    #   （sample-toolkit 有3条安全公告、sampledelegate 有2条，印证「有人在管」的都被审过）
    if d.get("security_md") is False:
        score += 20; facts += 20
        why.append("无SECURITY.md，安全响应不可靠（★反直觉规则）")
    elif d.get("security_md") is True:
        why.append("有SECURITY.md，安全流程完善（洞会被快速修），减分")

    # ---- 源码事实（最多 30，来自 probe）
    vd = d.get("verdict") or {}
    cbf = d.get("counts_by_file") or {}
    if d.get("ok"):
        if vd.get("has_http_endpoint"):
            score += 12; facts += 12
            why.append("源码确认对外提供HTTP端点（攻击面）")
        if vd.get("has_tool_registration"):
            score += 10; facts += 10
            why.append("有工具注册机制，二阶污点有落点")
        if vd.get("has_mcp_server"):
            score += 8; facts += 8
            why.append("提供MCP服务（Agent特有攻击面）")
        # 危险执行点：只作为「值得看」，不作为「有洞」
        nd = cbf.get("dangerous_exec", 0)
        if nd >= 20:
            score += 6; facts += 6
            why.append("危险执行点分布在%d个文件，值得细看" % nd)
        elif nd > 0:
            score += 3; facts += 3
            why.append("有危险执行点（%d个文件）" % nd)
        # 代码规模（排除测试/示例后的业务代码）
        nb = d.get("total_py_files")
        if nb is not None and nb >= 100:
            score += 4; facts += 4
            why.append("业务py文件%d个，规模够分析" % nb)
        elif nb is not None and nb < 20:
            why.append("业务py文件仅%d个，可能是玩具，减分" % nb)
    else:
        why.append("★未跑源码探针（API额度未恢复），攻击面未知 —— 分数偏低是应该的")

    # ---- 启发式类（最多 25，明确标注）
    if r.get("agent_verdict") == "yes":
        soft += 5
        why.append("多维信号确认是Agent项目（启发式+5）")
    elif r.get("agent_verdict") == "maybe":
        soft += 2
        why.append("部分信号像Agent项目，需人工确认（启发式+2）")
    else:
        why.append("不像Agent项目")

    py = r.get("pypi") or {}
    if py.get("found"):
        soft += 8
        why.append("PyPI可装 %s（%s发布）" % (py.get("version"), py.get("uploaded")))
    elif py.get("found") is False:
        why.append("PyPI未命中猜的包名（不等于装不上），需人工确认")

    # watcher 关注度过高 = 可能已被审计
    w = r.get("watchers") or 0
    if w and st and w / float(st) > 0.08:
        why.append("watcher/star比%.2f偏高，受关注度高" % (w / float(st)))

    score += soft
    r["score_parts"] = {"facts": facts, "soft": soft, "total": score}
    return score, why


def cmd_selftest(args):
    """Test the screening rules themselves. Offline, on synthetic repositories.

    This used to fetch repositories from the GitHub API and compare against canned answers
    about their upstream status. Two problems with that: it needed the network, and when the
    requests failed it printed "passed" anyway, having asserted nothing. A test that reports
    success when it checked nothing is worse than no test, because it is believed.

    So the cases below are built from dictionaries that look like search results, and the
    rules are what is being checked.
    """
    print("=" * 66)
    print("rule self-test (offline, synthetic inputs)")
    print("=" * 66)

    def ago(days: int) -> str:
        """A GitHub-style timestamp `days` in the past."""
        return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    active, stale = ago(10), ago(MAX_DAYS_SINCE_PUSH + 30)

    def repo(**kw):
        base = {
            "full_name": "someone/agent-kit",
            "name": "agent-kit",
            "description": "an LLM agent framework with tools to execute actions",
            "topics": ["llm", "agent", "tools"],
            "language": "Python",
            "archived": False,
            "fork": False,
            "pushed_at": active,
            "stargazers_count": (STAR_MIN + STAR_MAX) // 2,
        }
        base.update(kw)
        return base

    cases = [
        ("a live Python agent project passes", repo(), True),
        ("an archived repository is excluded", repo(archived=True), False),
        ("a fork is excluded", repo(fork=True), False),
        ("a non-Python repository is excluded", repo(language="Go"), False),
        ("a stale repository is excluded", repo(pushed_at=stale),
         False),
        ("a repository with no push date is excluded", repo(pushed_at=None), False),
        ("too many stars is excluded -- it has been audited already",
         repo(stargazers_count=STAR_MAX + 1000), False),
        ("too few stars is excluded", repo(stargazers_count=max(0, STAR_MIN - 1)), False),
        ("a project that does not look like an agent is excluded",
         repo(name="csv-tools", description="a small CSV helper", topics=["csv"]), False),
        ("an agent project with no tool/action signal is only a 'maybe', not a 'yes'",
         repo(description="an LLM agent framework", topics=["llm", "agent"]), True),
    ]

    failures = []
    for label, item, expect_pass in cases:
        passed, reasons = screen_item(item)
        ok = passed is expect_pass
        print(f"  [{'ok' if ok else 'FAIL'}] {label}")
        if not ok:
            print(f"        expected pass={expect_pass}, got pass={passed}; reasons={reasons}")
            failures.append(label)

    print()
    for name, desc, topics, expected in [
        ("agent-kit", "an LLM agent framework with tools to execute actions",
         ["llm", "agent"], "yes"),
        ("helper", "a small utility", ["utility"], "no"),
    ]:
        verdict, score, reasons = looks_like_agent(name, desc, topics)
        ok = verdict == expected
        print(f"  [{'ok' if ok else 'FAIL'}] looks_like_agent({name!r}) -> {verdict}"
              f" (expected {expected})")
        if not ok:
            failures.append(f"looks_like_agent({name!r})")

    print("=" * 66)
    if failures:
        print("self-test FAILED:")
        for f in failures:
            print(f"  [FAIL] {f}")
        return 1
    print(f"self-test passed: {len(cases) + 2} cases, none skipped")
    return 0


def _save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def main():
    import argparse
    p = argparse.ArgumentParser(description="Agent 漏洞目标筛选器")
    sub = p.add_subparsers(dest="cmd")

    pf = sub.add_parser("fetch", help="Layer 0 拉候选池")
    pf.add_argument("--query", action="append", help="自定义 search query（可多次）")

    ps = sub.add_parser("screen", help="Layer 1+2 硬性过滤 + PyPI")
    sub.add_parser("deep", help="Layer 3 深查（花额度）").add_argument(
        "--limit", type=int, default=0, help="只查前 N 个")
    pr = sub.add_parser("report", help="出候选清单")
    pr.add_argument("--top", type=int, default=0, help="只写前 N 个")
    sub.add_parser("selftest", help="验规则本身")
    sub.add_parser("resolve", help="把AgentFuzz目标解析成规范名（防改名漏排除）")

    a = p.parse_args()
    if a.cmd == "fetch":
        return cmd_fetch(a)
    if a.cmd == "screen":
        return cmd_screen(a)
    if a.cmd == "deep":
        return cmd_deep(a)
    if a.cmd == "report":
        return cmd_report(a)
    if a.cmd == "resolve":
        return cmd_resolve(a)
    if a.cmd == "selftest":
        return cmd_selftest(a)
    p.print_help()
    return 0


if __name__ == "__main__":
    import urllib.parse
    sys.exit(main())