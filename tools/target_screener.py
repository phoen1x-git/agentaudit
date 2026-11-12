#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Find and screen GitHub projects worth pointing the scanner at.
================================================================

The point is to turn "which project next" from a judgement call into a rule that runs, and
to produce a list you can argue with. Measured on five projects we picked by hand, four had
already been fixed or archived: the well-known ones were mined out. So selection has to
exclude two things on purpose, the very well known (already audited) and the well run
(has a SECURITY.md or advisories, so reports get fixed before they are interesting).

★ Every rule here is decided from data, with no human reading the repository.
  The layers exist because an unauthenticated GitHub search is 60 core requests per hour:

    layer 0  collect a pool       search API, one request per query
    layer 1  hard filters         fields the search response already carries, no request
    layer 2  installable          PyPI API, not rate limited
    layer 3  probe                GitHub core API, expensive, survivors only

What you are looking for is a profile, not a constant: `screen --profile your.yml`. See
core/config/screen_profile.example.yml. Without one, every user gets the same list, which is
the one thing this tool should not do.

Usage
-----
    agentaudit targets fetch      # layer 0
    agentaudit targets screen     # layer 1+2, cheap; --profile to say what you want
    agentaudit targets deep       # layer 3, costs quota
    agentaudit targets report     # the list; --excluded says what was dropped and why
    agentaudit targets selftest   # ★ run this first: it checks the rules themselves

★ Resumable: every API response is cached under _cache/, so a rerun costs nothing.
★ Rate limit: 60/hour unauthenticated. The script reads rate_limit and backs off; set
  GH_TOKEN to raise it to 5000.
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
                    print("    [rate limit] waiting %d s ..." % (reset + 5), flush=True)
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

# Defaults. A profile file overrides any of them; see core/config/screen_profile.example.yml.
DEFAULT_PROFILE = {
    "stars": [200, 5000],
    "max_days_since_push": 183,
    "languages": ["python"],
    # Empty means "any form". Otherwise keep only projects that match one of these.
    "forms": [],
    # report | fix | study. It changes the thresholds below, nothing else.
    "intent": "report",
    "skip_archived": True,
    "skip_fork": True,
    "skip_known": True,
}

# Named aliases for the defaults. The self-test asserts against these, and the fetch message
# quotes them; keeping them as names means the default lives in exactly one place.
STAR_MIN = DEFAULT_PROFILE["stars"][0]
STAR_MAX = DEFAULT_PROFILE["stars"][1]
MAX_DAYS_SINCE_PUSH = DEFAULT_PROFILE["max_days_since_push"]

# What a project *is*, judged from topics and the description alone: no extra request.
# Coarse on purpose. It answers "is this the kind of thing I want to read", not "what shape
# is its attack surface" -- that is the probes' job, later and far more expensive.
FORM_PATTERNS = {
    "mcp": re.compile(r"\bmcp\b|model context protocol", re.I),
    "web": re.compile(
        r"\b(web|http|rest|api|server|service|flask|fastapi|django|endpoint)s?\b", re.I),
    "cli": re.compile(r"\b(cli|command[- ]line|terminal|shell|console)\b", re.I),
    "library": re.compile(
        r"\b(library|sdk|framework|toolkit|package|wrapper|plugin)\b", re.I),
}


def infer_forms(it) -> set:
    text = " ".join([
        str(it.get("name") or ""),
        str(it.get("description") or ""),
        " ".join(str(t) for t in (it.get("topics") or [])),
    ])
    return {k for k, rx in FORM_PATTERNS.items() if rx.search(text)}


def load_profile(path) -> dict:
    """Read a profile file over the defaults. Unknown keys are an error, not a shrug.

    A misspelled key in a config file is the quiet kind of bug: the tool runs, ignores what
    you meant, and the output looks like an answer. So this refuses to guess.
    """
    cfg = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULT_PROFILE.items()}
    if not path:
        return _apply_intent(cfg)
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    unknown = sorted(set(raw) - set(cfg))
    if unknown:
        raise SystemExit(
            "unknown key(s) in profile %s: %s\nknown keys: %s"
            % (path, ", ".join(unknown), ", ".join(sorted(cfg))))
    for k, v in raw.items():
        if k == "forms":
            bad = sorted(set(v or []) - set(FORM_PATTERNS))
            if bad:
                raise SystemExit(
                    "unknown form(s) in profile: %s\nknown forms: %s"
                    % (", ".join(bad), ", ".join(sorted(FORM_PATTERNS))))
        if k in ("stars",) and (not isinstance(v, list) or len(v) != 2):
            raise SystemExit("profile key 'stars' must be [min, max]")
        cfg[k] = list(v) if isinstance(v, list) else v
    return _apply_intent(cfg)


def _apply_intent(cfg: dict) -> dict:
    """Intent narrows the thresholds. It is stated once, so it cannot be half-applied."""
    intent = cfg.get("intent") or "report"
    if intent == "report":
        # A project nobody maintains will not fix what you report.
        cfg["skip_archived"] = True
        cfg["max_days_since_push"] = min(cfg["max_days_since_push"], 183)
    elif intent == "fix":
        # You are going to patch it yourself, so it has to be alive.
        cfg["max_days_since_push"] = min(cfg["max_days_since_push"], 90)
    elif intent == "study":
        # Reading someone else's design does not require the project to be maintained, and a
        # well-known one is often the better read.
        cfg["skip_archived"] = False
        cfg["stars"] = [max(cfg["stars"][0], 0), 10 ** 9]
    else:
        raise SystemExit(
            "unknown intent '%s' in profile; use report, fix or study" % intent)
    return cfg


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


def screen_item(it, cfg=None):
    """Run the hard filters over one candidate. Returns (passed?, reasons).

    ★ Reads only fields that the search response already carries: no extra request.
    Every reason is recorded whether the item passes or not, so a later report can say why
    something was left out. A filter whose exclusions are invisible cannot be argued with.
    """
    cfg = cfg or _apply_intent(dict(DEFAULT_PROFILE))
    full = (it.get("full_name") or "").lower()
    reasons = []

    # 1) already measured, by us or by the paper this pipeline came from. Both the old and
    #    the new name count, because a rename would otherwise walk straight past this.
    if cfg.get("skip_known", True) and is_paper_target(full):
        return False, ["already measured (this project, or the paper)"]

    # 2) archived: nobody will fix what you report
    if it.get("archived") and cfg.get("skip_archived", True):
        reasons.append("archived")

    # 3) fork: upstream does not accept reports about forks, and fixes do not travel back
    if it.get("fork") and cfg.get("skip_fork", True):
        reasons.append("fork")

    # 4) language: the pipeline's static frontend reads specific languages only
    lang = (it.get("language") or "").lower()
    wanted = [str(x).lower() for x in (cfg.get("languages") or [])]
    if wanted and lang not in wanted:
        reasons.append("language %s (wanted %s)" % (lang or "?", "/".join(wanted)))

    # 5) form: what kind of thing it is, from topics and description only
    if cfg.get("forms"):
        forms = infer_forms(it)
        if not (forms & set(cfg["forms"])):
            reasons.append("form none of %s (looks like %s)"
                           % ("/".join(cfg["forms"]), "/".join(sorted(forms)) or "unknown"))

    # 6) activity
    d = days_since(it.get("pushed_at"))
    if d is None:
        reasons.append("no pushed_at")
    elif d > cfg["max_days_since_push"]:
        reasons.append("idle %d days (limit %d)" % (d, cfg["max_days_since_push"]))

    # 7) star band
    st = it.get("stargazers_count") or 0
    lo, hi = cfg["stars"][0], cfg["stars"][1]
    if st > hi:
        reasons.append("stars %d above %d (heavily audited)" % (st, hi))
    elif st < lo:
        reasons.append("stars %d below %d" % (st, lo))

    # 8) does it look like an agent project at all
    verdict, score, rs = looks_like_agent(
        it.get("name"), it.get("description"), it.get("topics"))
    if verdict == "no":
        reasons.append("not agent-like")
    else:
        reasons.append("agent signal [%s] %s" % (verdict, "+".join(rs) or "-"))

    return (len(reasons) == 0 or
            (reasons and reasons[0].startswith("agent signal"))), reasons


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
    print("resolving the canonical name of %d repositories...\n" % len(names))
    changed = []
    for i, n in enumerate(names, 1):
        d = http_json("https://api.github.com/repos/%s" % n)
        real = None
        if isinstance(d, dict) and d.get("full_name"):
            real = d["full_name"]
        elif isinstance(d, dict) and d.get("message") == "Not Found":
            print("[%2d/%d] %-38s !! 404: deleted, or moved to another owner"
              % (i, len(names), n))
        else:
            print("[%2d/%d] %-38s ?? %s" % (
                i, len(names), n, str(d.get("message") or d.get("_error"))[:50]))

        if real:
            cm[n.lower()] = real.lower()
            if real.lower() != n.lower():
                changed.append((n, real))
                print("[%2d/%d] %-38s -> %s  ★renamed" % (i, len(names), n, real))
            else:
                print("[%2d/%d] %-38s    name unchanged" % (i, len(names), n))
        time.sleep(1.0)

    _CANON_MEM.clear()
    _CANON_MEM.update(cm)
    _save(CANON_FILE, cm)
    print("\nrenamed or moved: %d" % len(changed))
    for a, b in changed:
        print("  %s  ->  %s" % (a, b))
    print("\n-> %s" % CANON_FILE)
    if changed:
        print("\n★ the exclusion list now holds both the old and the new name, so a "
          "rename cannot slip past it.")
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
        print("        total=%s  fetched=%d" % (d.get("total_count"), len(items)))
        for it in items:
            fn = it.get("full_name")
            if fn:
                pool["repos"][fn.lower()] = it
        time.sleep(7)   # search 未认证 10 次/分钟，礼貌等待

    pool["queries"] = queries
    pool["fetched_at"] = now_utc()
    _save(POOL_FILE, pool)
    print("\npool holds %d repositories -> %s" % (len(pool["repos"]), POOL_FILE))


def _date_ago(days):
    dt = datetime.now(timezone.utc).timestamp() - days * 86400
    return datetime.fromtimestamp(dt, timezone.utc).strftime("%Y-%m-%d")


def cmd_screen(args):
    """Layer 1+2：硬性过滤 + PyPI 可装性。便宜，全量跑。"""
    cfg = load_profile(getattr(args, "profile", None))
    pool = load_pool()
    repos = pool.get("repos") or {}
    if not repos:
        print("the pool is empty: run `fetch` first", file=sys.stderr)
        return 1

    out = []
    for full, it in sorted(repos.items()):
        ok, reasons = screen_item(it, cfg)
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

    _save(SCREEN_FILE, {"screened_at": now_utc(), "items": out, "profile": cfg})

    n1 = sum(1 for r in out if r["passed_L1"])
    n2 = sum(1 for r in out if r.get("passed_L2"))
    print("candidates %d -> passed filters %d -> installable via PyPI %d"
          % (len(out), n1, n2))
    print("profile: intent=%s stars=%s idle<=%dd forms=%s" % (
        cfg.get("intent"), cfg["stars"], cfg["max_days_since_push"],
        "/".join(cfg.get("forms") or []) or "any"))
    print("-> %s" % SCREEN_FILE)
    return 0


def cmd_deep(args):
    """Layer 3：对入围者深查。★ 花 core 额度，注意限流。"""
    if not os.path.exists(SCREEN_FILE):
        print("nothing screened yet: run `screen` first", file=sys.stderr)
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

    print("quota: %s" % rate_limit())
    results = {}
    for i, t in enumerate(targets, 1):
        fn = t["full_name"]
        key = fn.lower()
        if key in byname and byname[key].get("tree_ok"):
            print("[%d/%d] %s  (cached)" % (i, len(targets), fn))
            results[key] = byname[key]
            continue
        print("[%d/%d] %s" % (i, len(targets), fn), flush=True)
        results[key] = deep_one(fn, t.get("default_branch") or "main")
        # 每 10 个存一次盘，中断也不丢
        if i % 10 == 0:
            _save(DEEP_FILE, {"deep_at": now_utc(), "items": results})
        time.sleep(1.0)

    _save(DEEP_FILE, {"deep_at": now_utc(), "items": results})
    print("probed %d -> %s" % (len(results), DEEP_FILE))
    return 0


def cmd_report(args):
    """Write the candidate list as Markdown, plus a short console summary.

    Two lists, not one. The candidates are what you would open next; the exclusions are what
    the filters rejected and why. Without the second list a reader cannot tell "nothing else
    was found" from "everything else was thrown away for a reason I would disagree with",
    and a filter nobody can inspect is a filter nobody can correct.
    """
    if not os.path.exists(SCREEN_FILE):
        print("nothing screened yet: run `screen` first", file=sys.stderr)
        return 1
    with open(SCREEN_FILE, "r", encoding="utf-8") as f:
        scr = json.load(f)
    deep = {}
    if os.path.exists(DEEP_FILE):
        with open(DEEP_FILE, "r", encoding="utf-8") as f:
            deep = {k.lower(): v for k, v in
                    (json.load(f).get("items") or {}).items()}

    rows = []
    dropped = []
    for r in scr["items"]:
        if not r.get("passed_L1"):
            dropped.append(r)
            continue
        d = deep.get(r["full_name"].lower()) or {}
        score, why = score_target(r, d)
        rows.append((score, r, d, why))

    rows.sort(key=lambda x: -x[0])
    top = rows[:args.top] if args.top else rows

    prof = scr.get("profile") or {}
    stars = prof.get("stars") or [200, 5000]

    lines = []
    lines.append("# Candidate targets\n")
    lines.append("Generated: %s\n" % scr.get("screened_at"))
    lines.append(
        "Filter: intent `%s`, stars %s-%s, idle at most %s days, forms %s, languages %s\n"
        % (prof.get("intent", "report"), stars[0], stars[1],
           prof.get("max_days_since_push", "?"),
           "/".join(prof.get("forms") or []) or "any",
           "/".join(prof.get("languages") or []) or "any"))
    lines.append("## Read this before you trust the numbers\n")
    lines.append("| Marker | Meaning |")
    lines.append("|---|---|")
    lines.append("| `—` | **not checked** (which is not the same as \"none\") |")
    lines.append("| `none` | checked, and there is none |")
    lines.append("")
    lines.append("- `agent_verdict` is a **heuristic** (a vote over topics and description "
                 "words). It is not a hard rule and it is excluded from the fact score.")
    lines.append("- `PyPI no` only means the **guessed** package name was not found. "
                 "Guessing the name wrong is common; it does not mean the project "
                 "cannot be installed.")
    lines.append("- A project with **no probe data** has an **unknown** attack surface. "
                 "A low score there reflects missing data, not a bad project. "
                 "**Do not pick work off the ranking alone**; fill in the probe data first.")
    lines.append("- The **fact score** (stars, activity, SECURITY.md, source signals) and "
                 "the **heuristic score** (agent-likeness, PyPI) are kept apart; see "
                 "`score_parts` on each entry.")
    lines.append("")

    lines.append("## Selected\n")
    lines.append("| Score | of which facts | Project | stars | last push | SECURITY.md | probe |")
    lines.append("|---|---|---|---|---|---|---|")
    for score, r, d, why in top:
        sec = {True: "yes", False: "no", None: "—"}.get(d.get("security_md"), "—")
        if d.get("ok"):
            vd = d.get("verdict") or {}
            marks = []
            if vd.get("has_http_endpoint"):
                marks.append("HTTP")
            if vd.get("has_mcp_server"):
                marks.append("MCP")
            if vd.get("has_tool_registration"):
                marks.append("tools")
            if vd.get("has_dangerous_exec"):
                marks.append("exec")
            probe_s = "+".join(marks) if marks else "no hits"
        else:
            probe_s = "—not run"
        sp = r.get("score_parts") or {}
        lines.append("| %d | %s | [%s](%s) | %s | %s days ago | %s | %s |" % (
            score, sp.get("facts", "—"), r["full_name"], r.get("html_url") or "",
            r.get("stars"), r.get("days_since_push"), sec, probe_s))
    lines.append("")

    lines.append("## Why each score\n")
    for score, r, d, why in top:
        lines.append("### %s (score %d)\n" % (r["full_name"], score))
        lines.append("- description: %s" % (r.get("desc") or "(none)"))
        lines.append("- agent signal: %s (score=%s)" % (r.get("agent_verdict"),
                                                       r.get("agent_score")))
        lines.append("- filter reasons: %s" % "; ".join(r.get("reasons") or []))
        py = r.get("pypi") or {}
        if py:
            lines.append("- PyPI: %s" % (
                "%s %s (released %s, requires_python=%s)" % (
                    py.get("name"), py.get("version"), py.get("uploaded"),
                    py.get("requires_python")) if py.get("found")
                else "guessed name %s not on PyPI (which does not mean it cannot be "
                     "installed)" % r.get("pypi_guess")))
        if d:
            # ★ Only show what was actually measured. "Not checked" never becomes "none".
            bits = []
            if d.get("ok"):
                vd = d.get("verdict") or {}
                cbf = d.get("counts_by_file") or {}
                bits.append("sampled %s/%s py files%s" % (
                    d.get("sampled_files"), d.get("total_py_files"),
                    " (★sample, not full)" if d.get("sampled_files") else ""))
                for k, lab in [("has_http_endpoint", "HTTP endpoint"),
                               ("has_mcp_server", "MCP server"),
                               ("has_tool_registration", "tool registration"),
                               ("has_dangerous_exec", "dangerous exec"),
                               ("has_auth_surface", "auth surface")]:
                    bits.append("%s:%s" % (lab, "yes" if vd.get(k) else "no"))
                if cbf.get("dangerous_exec"):
                    bits.append("dangerous exec in %d files"
                                % cbf["dangerous_exec"])
                colo = vd.get("colocated_files") or []
                if colo:
                    bits.append("★★dangerous call next to external input in "
                                + ", ".join(colo[:3]))
            sec = d.get("security_md")
            if sec is not None:
                bits.append("SECURITY.md:%s" % ("yes" if sec else "no"))
            else:
                bits.append("SECURITY.md:not checked")
            if bits:
                lines.append("- source/probe: " + "; ".join(bits))
            lines.append("- score split: %s" % json.dumps(
                r.get("score_parts") or {}, ensure_ascii=False))
        else:
            lines.append("- source/probe: ★**not run** (the GitHub core quota resets "
                         "hourly and was spent). The attack surface is unknown, which is "
                         "not the same as absent.")
        lines.append("- **why this score**: %s\n" % "; ".join(why))

    if args.excluded and dropped:
        lines.append("## Filtered out\n")
        lines.append("| Project | stars | why it was dropped |")
        lines.append("|---|---|---|")
        for r in sorted(dropped, key=lambda x: -(x.get("stars") or 0)):
            lines.append("| [%s](%s) | %s | %s |" % (
                r["full_name"], r.get("html_url") or "", r.get("stars"),
                "; ".join(r.get("reasons") or []) or "—"))
        lines.append("")
        lines.append("A reason in this table is the filter speaking, not a finding about "
                     "the project. Several of them are about your own profile: change "
                     "the profile and the same project can move to the list above.\n")

    md = os.path.join(OUT, "candidates.md")
    with open(md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("-> %s" % md)

    print("\n===== top 15 (console view) =====")
    for score, r, d, why in rows[:15]:
        print("%3d  %-42s star=%-6s push=%s days ago  %s" % (
            score, r["full_name"], r.get("stars"), r.get("days_since_push"),
            "; ".join(why)[:70]))
    if dropped:
        print("\n%d project(s) filtered out; `--excluded` lists them with the reason."
              % len(dropped))
    return 0


def score_target(r, d):
    """Score a target 0-100. Every point has to come with a reason you can check.

    ★ Only verifiable facts count as facts:
      - stars / pushed_at / archived come from the GitHub API
      - SECURITY.md is looked up by filename in the tree
      - HTTP endpoint / tool registration / dangerous exec come from the source probe
      - "does it look like an agent" is a heuristic, labelled as one and kept out of
        the fact score
    """
    score = 0
    why = []
    facts = 0          # the verifiable part
    soft = 0           # the heuristic part

    # ---- 事实类（满分 75）
    # 中腰部最优：太低不可信，太高被审计
    st = r.get("stars") or 0
    if 300 <= st <= 2000:
        score += 25; facts += 25
        why.append("mid-band stars (%d): audited less than the leaders" % st)
    elif 200 <= st <= 3000:
        score += 15; facts += 15
        why.append("moderate stars (%d)" % st)
    else:
        why.append("stars outside the mid band (%d)" % st)

    # 近期活跃
    dd = r.get("days_since_push")
    if dd is not None:
        if dd <= 30:
            score += 20; facts += 20
            why.append("pushed %d days ago, active" % dd)
        elif dd <= 90:
            score += 12; facts += 12
            why.append("pushed %d days ago" % dd)
        else:
            why.append("pushed %d days ago, going cold" % dd)

    # ★ 反直觉规则：没有 SECURITY.md = 没人管安全 = 洞不会被快速修掉
    #   （sample-toolkit 有3条安全公告、sampledelegate 有2条，印证「有人在管」的都被审过）
    if d.get("security_md") is False:
        score += 20; facts += 20
        why.append("no SECURITY.md: reports will not be handled quickly "
                   "(★counter-intuitive rule)")
    elif d.get("security_md") is True:
        why.append("has SECURITY.md: reports get fixed fast, so this scores lower")

    # ---- 源码事实（最多 30，来自 probe）
    vd = d.get("verdict") or {}
    cbf = d.get("counts_by_file") or {}
    if d.get("ok"):
        if vd.get("has_http_endpoint"):
            score += 12; facts += 12
            why.append("source confirms an HTTP endpoint (attack surface)")
        if vd.get("has_tool_registration"):
            score += 10; facts += 10
            why.append("has tool registration: second-order taint has somewhere to land")
        if vd.get("has_mcp_server"):
            score += 8; facts += 8
            why.append("runs an MCP server (an attack surface specific to agents)")
        # 危险执行点：只作为「值得看」，不作为「有洞」
        nd = cbf.get("dangerous_exec", 0)
        if nd >= 20:
            score += 6; facts += 6
            why.append("dangerous calls spread over %d files: worth reading" % nd)
        elif nd > 0:
            score += 3; facts += 3
            why.append("has dangerous calls (%d files)" % nd)
        # 代码规模（排除测试/示例后的业务代码）
        nb = d.get("total_py_files")
        if nb is not None and nb >= 100:
            score += 4; facts += 4
            why.append("%d non-test py files: enough code to analyse" % nb)
        elif nb is not None and nb < 20:
            why.append("only %d non-test py files: possibly a toy" % nb)
    else:
        why.append("★source probe not run (API quota not recovered): the attack "
                   "surface is unknown, so a low score here is expected")

    # ---- 启发式类（最多 25，明确标注）
    if r.get("agent_verdict") == "yes":
        soft += 5
        why.append("several independent signals say agent project (heuristic +5)")
    elif r.get("agent_verdict") == "maybe":
        soft += 2
        why.append("some signals look agent-like, needs a human (heuristic +2)")
    else:
        why.append("does not look like an agent project")

    py = r.get("pypi") or {}
    if py.get("found"):
        soft += 8
        why.append("installable from PyPI %s (released %s)"
                   % (py.get("version"), py.get("uploaded")))
    elif py.get("found") is False:
        why.append("guessed package name not on PyPI (not the same as "
                   "uninstallable), needs a human")

    # watcher 关注度过高 = 可能已被审计
    w = r.get("watchers") or 0
    if w and st and w / float(st) > 0.08:
        why.append("watcher/star ratio %.2f is high: well watched" % (w / float(st)))

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
    p = argparse.ArgumentParser(
        prog="agentaudit targets",
        description="Find and screen GitHub projects that are worth pointing the scanner at.",
        epilog="Run `selftest` first: it checks the rules themselves against synthetic cases.")
    sub = p.add_subparsers(dest="cmd")

    pf = sub.add_parser("fetch", help="layer 0: collect a candidate pool from search")
    pf.add_argument("--query", action="append",
                    help="extra search query, repeatable (default: a built-in set)")

    ps = sub.add_parser(
        "screen", help="layer 1+2: apply the hard filters, then check PyPI")
    ps.add_argument("--profile", metavar="FILE",
                    help="YAML profile of what you are looking for "
                         "(see core/config/screen_profile.example.yml)")

    pd = sub.add_parser("deep", help="layer 3: probe the survivors (costs API quota)")
    pd.add_argument("--limit", type=int, default=0, help="probe only the first N")

    pr = sub.add_parser("report", help="write the candidate list as Markdown")
    pr.add_argument("--top", type=int, default=0, help="write only the top N")
    pr.add_argument("--excluded", action="store_true",
                    help="also list what was filtered out, with the reason for each")

    sub.add_parser("selftest", help="check the screening rules themselves")
    sub.add_parser(
        "resolve", help="resolve known target names to their current canonical name, "
                        "so a rename does not slip past the exclusion list")

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