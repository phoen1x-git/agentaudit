#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
按需取源码（省额度版）
======================

背景与踩坑（2026-10-04）
-----------------------
要让规则落到源码上，第一反应是 `git clone`。实测在这台机器上：

    git clone → CONNECT tunnel failed, response 502   （8/8 全失败）
    git 不用代理 → Could not connect to server:443
    curl 下tarball → 能通，但只有 ~58 KB/s，一个 15MB 仓库要 4 分钟+
    GitHub API（curl）→ 200，稳定

★ 结论：**git 这条路被代理挡死了（CONNECT 不放行），不是配置问题。**
  硬啃下载也不划算（半小时起步）。
  → 改走GitHub API「按需取文件」：树1 次 + 关键文件少量。

代价与取舍（说清楚，不藏着）
-----------------------------
    完整扫描（所有文件）  → 要 clone，本机做不到
    按需取关键文件        → 每目标约 3~5 次请求，core 额度 60/小时 够用

★ **所以这个探针给的是「抽样证据」，不是全量覆盖。**
  报告里必须按抽样约定写，不能说「已扫描全部源码」。
  （这是我把它叫 probe 而不是 scanner 的原因 —— 探针本来就是抽样的。）

规则与 probe_attack_surface.py 相同，但只作用于取到的文件。
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(HERE, "..", "data", "target_pool", "_src_cache")
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

CODE_EXT = (".py", ".ts", ".js")


def _cache(name):
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


def api_get(url, cache_name, force=False):
    """带磁盘缓存的 API GET。缓存命中不花额度。"""
    cp = _cache(re.sub(r"[^A-Za-z0-9_.-]", "_", cache_name)[:170] + ".json")
    if not force and os.path.exists(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    hdr = {"User-Agent": "target-screener/1.0",
           "Accept": "application/vnd.github+json"}
    if TOKEN:
        hdr["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(url, headers=hdr)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                data = json.loads(r.read().decode("utf-8"))
            with open(cp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            return data
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                reset = None
                try:
                    reset = int(e.headers.get("x-ratelimit-reset") or 0) - int(time.time())
                except Exception:
                    pass
                if reset and reset < 3700 and attempt < 2:
                    print("      [限流] 等待 %d 秒" % (reset + 5), flush=True)
                    time.sleep(reset + 5)
                    continue
            return {"_error": "HTTP %s" % e.code, "_status": e.code}
        except Exception as e:
            if attempt < 2:
                time.sleep(3)
            else:
                return {"_error": "%s: %s" % (type(e).__name__, e)}
    return {"_error": "重试耗尽"}


def api_raw(full_name, path, branch, cache_name):
    """取单个文件的原始文本。走 contents + raw Accept。"""
    cp = _cache(re.sub(r"[^A-Za-z0-9_.-]", "_", cache_name)[:170] + ".txt")
    if os.path.exists(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    url = ("https://api.github.com/repos/%s/contents/%s?ref=%s"
           % (full_name, urllib.parse.quote(path), branch))
    hdr = {"User-Agent": "target-screener/1.0",
           "Accept": "application/vnd.github.raw"}
    if TOKEN:
        hdr["Authorization"] = "Bearer " + TOKEN
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=hdr),
                                    timeout=45) as r:
            txt = r.read().decode("utf-8", "replace")
        with open(cp, "w", encoding="utf-8") as f:
            f.write(txt)
        return txt
    except Exception as e:
        return ""      # 取不到就当没有，不假装


# ---------------------------------------------------------------- 挑关键文件

EXCLUDE_RE = re.compile(
    r"(^|/)(\.git|\.venv|venv|site-packages|node_modules|_vendor|vendor|"
    r"third_party|tests?|testing|examples?|samples?|docs?|demos?|migrations?|"
    r"\bdocs?\b)(/|$)")


def pick_key_files(paths, max_files=40):
    """★ 按「能力」挑文件，不按名字匹配（教训：按名字匹配=换个名字就瞎）。

    ★★ 第一版只按「名字像 server/tool/app」的挑，结果在 samplecli 上翻了车：
      它是 shell agent，真正的执行逻辑在 src/samplecli/client/bash_state/ 下，
      目录名里没有 server/api/tool → 优先级 0 → 一个都没抽到。
      → 而那正是最该看的文件。
      → 教训：**抽样会漏掉最关键的文件**，而漏掉的位置是系统性的
        （不是随机漏，是「名字不告诉你它重要」的那些全漏）。
      所以：① 给「可能被漏」的路径兜底保底名额
            ② 把抽样比例与约定都写进报告，不假装是全量。
    """
    py = [p for p in paths if p.endswith(".py")]

    def ok(p):
        return not EXCLUDE_RE.search(p) and not p.endswith("__init__.py")

    # ---------- A. 高优先级：名字明确指示职责的
    prio = []
    for p in py:
        if not ok(p):
            continue
        lp = p.lower()
        b = os.path.basename(lp)
        s = 0
        if re.search(r"(^|/)(server|webapp|backend|api|apis|routes|handlers?|"
                     r"controllers?|endpoints?|a2a)(/|\.|_)", lp):
            s += 60
        if re.search(r"\b(server|app|web|api|main|cli|run|asgi|wsgi)\.py$", b):
            s += 30
        if re.search(r"(^|/)(tools?|plugins?|skills?|functions?|toolkit|mcp)(/|\.|_)", lp):
            s += 40
        if re.search(r"\b(registry|register|base|factory|manager|loader)\w*\.py$", b):
            s += 20
        if b in ("main.py", "__main__.py", "app.py", "server.py", "cli.py"):
            s += 35
        if s:
            prio.append((s, len(p), p))
    prio.sort(key=lambda x: (-x[0], x[1]))

    # ---------- B. ★ 兜底：按「能力关键词」捞「名字不告诉你它重要」的文件
    #    这些路径名看起来无关，但常是执行/解析的核心：
    #    bash_state / shell / exec / sandbox / session / command / shell_state...
    SUSPECT_DIR = re.compile(
        r"(^|/)(bash_?state|shell|exec|execution|sandbox|session|command|"
        r"cmd|interpreter|runner|process|pty|terminal|container|docker|"
        r"kernel|worker|daemon|dispatch|inject|hook|plugin)(/|\.|_)", re.I)
    SUSPECT_FILE = re.compile(
        r"\b(bash|shell|exec|command|process|sandbox|session|parse|parser|"
        r"eval|interpreter|runner|container|pty)\w*\.py$", re.I)
    suspects = []
    for p in py:
        if not ok(p):
            continue
        if any(k in p for k in ("/picked",)):
            continue
        if SUSPECT_DIR.search(p) or SUSPECT_FILE.search(os.path.basename(p)):
            suspects.append((len(p), p))
    suspects.sort()

    # ★ 兜底名额：给可疑路径留一半预算
    n_susp = min(len(suspects), max(4, max_files // 3))
    picked = [p for _, _, p in prio[:max_files - n_susp - 2]]
    picked += [p for _, p in suspects[:n_susp]]

    # ★ 覆盖兜底：保证至少取到总量的一定比例。
    #
    #   实测踩过（同一个盲区的第二种表现）：
    #     digital-oracle 有 26 个业务文件（排除 test 后），
    #     但只有 web.py / base.py 命中关键词，
    #     其余 24 个（cache.py / http.py / proxy_pool.py / concurrent.py…）
    #     优先级全0 → 原逻辑「关键词命中者先占满 max_files」把配额用完，
    #     结果只抽到 2/52 = 4%。
    #
    #   → 与 samplecli 那次（执行逻辑在 client/bash_state/ 下，一个没抽到）
    #     **是同一个病**：抽样全靠关键词判断，名字不告诉你的就抽不到。
    #   → 修法：**在按关键词分配之后，强制按总量补足**。
    #     覆盖率是硬要求，优先级只是优化目标。
    if not max_files:
        max_files = int(os.environ.get("AF2O_MAX_FILES", "16"))
    avail = [p for p in py if ok(p)]
    min_ratio = float(os.environ.get("AF2O_MIN_COVER", "0.45"))
    floor = min(len(avail), max(4, int(round(len(avail) * min_ratio))))
    # ★★ 强制按总量补足 —— 这一段曾经被误删，导致兜底形同虚设
    if len(picked) < floor:
        already = set(picked)
        rest = sorted((p for p in avail if p not in already), key=len)
        for p in rest[:floor - len(picked)]:
            picked.append(p)

    # 补上配置文件
    for cfg in ("pyproject.toml", "setup.py", "requirements.txt"):
        if cfg in paths:
            picked.append(cfg)

    # 去重并保持顺序（★ 必须去重：兜底补足可能与前面的名单重叠）
    seen = set()
    out = []
    for p in picked:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


# ---------------------------------------------------------------- 主流程

def probe_remote(full_name, branch, max_files=None, verbose=True):
    """对远端仓库做抽样探针。返回证据报告。

    ★ max_files 默认走环境变量 AF2O_MAX_FILES：
      未认证时 60 次/小时 → 16 个（省额度）
      有token（5000/小时）→ 可以放到 200+
      这就是「额度决定覆盖率」的直接体现。
    """
    if max_files is None:
        max_files = int(os.environ.get("AF2O_MAX_FILES", "16"))
    tree = api_get("https://api.github.com/repos/%s/git/trees/%s?recursive=1"
                   % (full_name, branch), "tree__%s__%s" % (full_name, branch))
    entries = tree.get("tree") or []
    if not entries:
        return {"ok": False,
                "error": tree.get("_error") or tree.get("message") or "空树"}
    paths = [e.get("path") or "" for e in entries
             if e.get("type") in (None, "blob")]
    low = [p.lower() for p in paths]
    py_paths = [p for p in paths if p.endswith(".py")]

    picked = pick_key_files(paths, max_files)
    if verbose:
        print("      树 %d 项 / py %d 个 → 抽样 %d 个文件"
              % (len(paths), len(py_paths), len(picked)))

    sys.path.insert(0, HERE)
    import probe_attack_surface as pas

    files = {}
    for i, p in enumerate(picked, 1):
        txt = api_raw(full_name, p, branch, "f__%s__%s" % (full_name, p))
        if not txt:
            continue
        # ★ 配置类文件也存下来（summarize 会对文本跑规则，toml 无命中，无害），
        #   这样报告里能看到"取到了哪些文件"
        files[p] = txt
        if verbose and i % 10 == 0:
            print("      已取 %d/%d" % (i, len(picked)), flush=True)

    rep = pas.summarize(files, extra={
        "total_tree_entries": len(paths),
        "total_py_files": len(py_paths),
        "sampled_files": len(picked),
        "fetched_files": len(files),
        "truncated": bool(tree.get("truncated")),
        "coverage_note": ("★ 这是抽样（%d/%d 个 py 文件），不是全量扫描。"
                          "git clone 在本机被代理挡住（CONNECT 502），"
                          "所以只能按需取关键文件。"
                          % (len(picked), len(py_paths))),
    })
    rep["ok"] = True
    return rep


if __name__ == "__main__":
    import urllib.parse
    if len(sys.argv) < 2:
        print("用法: python fetch_src_probe.py <owner/repo> [branch] [max_files]")
        sys.exit(1)
    repo = sys.argv[1]
    br = sys.argv[2] if len(sys.argv) > 2 else "main"
    mx = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    r = probe_remote(repo, br, max_files=mx)
    if not r.get("ok"):
        print("失败：%s" % r.get("error"))
        sys.exit(1)
    print("\n文件 %d 个（抽样 %d / 共 %d 个py）"
          % (r["fetched_files"], r["sampled_files"], r["total_py_files"]))
    print("覆盖约定：%s" % r["coverage_note"])
    for k, label in [("has_http_endpoint", "HTTP端点"),
                     ("has_mcp_server", "MCP服务"),
                     ("has_tool_registration", "工具注册"),
                     ("has_dangerous_exec", "危险执行点"),
                     ("has_auth_surface", "认证鉴权"),
                     ("dangerous_and_input_colocated", "危险点与输入共现")]:
        print("  %-4s %s" % ("[有]" if r["verdict"][k] else "[无]", label))
    print("\n各类命中（全量/文件数）：")
    for k in sorted(r["counts"], key=lambda x: -r["counts"][x]):
        if r["counts"][k]:
            print("   %-20s %5d 处 / %3d 文件" % (
                k, r["counts"][k], r["counts_by_file"][k]))