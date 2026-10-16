"""内核 · 上游核实（发信前的硬前置）。

★ 为什么这一步不可省：报告里"上游状态"那句必须**由实际查询动作**填充。
  而且——**报漏洞前必须 fetch 上游 main**（踩过的教训：手上是几个月前的快照，
  版本号不代表"还没修"）。

做三件事：
  ① default_branch 是什么（★ 别再凭印象用 main）
  ② 用【特征串】而不是行号，去最新代码里找这处还在不在
  ③ 查该包/该仓库有没有已公开的安全公告

★ 只写"我们查了哪些渠道、什么时间、结论是什么"；
  **不许**写成"此漏洞从未被发现"——那超出我们实际做的动作。
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

from . import gh  # ★ GitHub 客户端只放一份（core/gh.py）

_ROOT = Path(__file__).resolve().parent.parent
_CFG = Path(__file__).resolve().parent / "config" / "upstream_repos.yml"
API = gh.API

_CACHE_DIR = _ROOT / "data" / "upstream_cache"


def _token() -> str:
    return gh.token()


def _get(url: str, raw: bool = False, tok: str | None = None) -> tuple[int, str]:
    return gh.get(url, raw=raw, tok=tok)


def load_cfg() -> dict:
    with open(_CFG, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def _cache_path(repo: str, path: str, ref: str) -> Path:
    safe = f"{repo.replace('/', '__')}__{path.replace('/', '__')}__{ref[:12]}"
    return _CACHE_DIR / (safe + ".txt")


def fetch_file(repo: str, path: str, ref: str, tok: str) -> tuple[str, str]:
    """取上游某文件内容（带磁盘缓存）。返回 (status, content)。"""
    cp = _cache_path(repo, path, ref)
    if cp.exists():
        return "cached", cp.read_text(encoding="utf-8", errors="replace")
    code, body = _get(f"{API}/repos/{repo}/contents/{path}?ref={ref}", raw=True, tok=tok)
    if code == 200:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cp.write_text(body, encoding="utf-8")
        return "ok", body
    return f"http{code}", body


_TREE_CACHE: dict = {}
_REPO_CACHE: dict = {}


def repo_for(project: str, cfg: dict | None = None) -> str:
    """★ 仓库坐标解析（**单一实现**，本模块是所有调用方的唯一来源）。

    ① 优先 `core/config/upstream_repos.yml`（手工维护，可额外放 packages 名）；
    ② ★★ **回退到 `targets*.yml` 的 `repo:` 字段** —— 目标池里**每个目标都有**这一条，
       而 `upstream_repos.yml` 到 只手工维护了 **3 条**（three sample projects）。
       不回退的后果：对**所有新目标**都变成"没配坐标 → 没查成"，
       而 `run()` 又把它打印成"上游文件已不存在" → ★ **一个看起来像"查过了"的假 0**。

    ★ 允许 `cfg=None`（工具单独调用时不必先读 yml）。
    """
    if cfg:
        r = (cfg.get("repos") or {}).get(project)
        if r:
            return r
    if project in _REPO_CACHE:
        return _REPO_CACHE[project]
    import glob as _glob
    for y in _glob.glob(str(_ROOT / "core" / "config" / "targets*.yml")):
        try:
            lines = open(y, encoding="utf-8").read().splitlines()
        except Exception:
            continue
        cur = None
        for ln in lines:
            mo = re.match(r"^  ([A-Za-z_.\-]+):\s*$", ln)
            if mo:
                cur = mo.group(1)
                continue
            mr = re.match(r"^\s+repo:\s*(\S+)\s*$", ln)
            if mr and cur:
                _REPO_CACHE.setdefault(cur, mr.group(1))
                cur = None
    return _REPO_CACHE.get(project, "")


def repo_tree(repo: str, ref: str, tok: str) -> list[str]:
    """整棵文件树（带缓存）。用途：文件 404 时判断是**改名/挪走了**还是**真删了**。"""
    key = (repo, ref)
    if key in _TREE_CACHE:
        return _TREE_CACHE[key]
    cp = _CACHE_DIR / (repo.replace("/", "__") + f"__tree__{ref[:12]}.json")
    if cp.exists():
        data = json.loads(cp.read_text(encoding="utf-8"))
    else:
        code, body = _get(f"{API}/repos/{repo}/git/trees/{ref}?recursive=1", tok=tok)
        data = ([x["path"] for x in json.loads(body).get("tree", []) if x.get("type") == "blob"]
                if code == 200 else [])
        if data:
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cp.write_text(json.dumps(data), encoding="utf-8")
    _TREE_CACHE[key] = data
    return data


def _locate(content: str, snippet: str) -> tuple[bool, int | None]:
    """用【特征串】在文件里定位（★ 不用行号）。先整行精确，再退一步用稳定片段。"""
    lines = content.splitlines()
    target = _norm(snippet)
    for i, l in enumerate(lines, 1):
        if _norm(l) == target:
            return True, i
    # ★ 宽松匹配必须用【有辨识度】的片段：像 "exec"、"eval" 这种内置名太泛，
    #   会命中一大片无关代码，造成"上游还在"的假阳性。
    if target:
        frag = target.split("(")[0][-40:]
        if len(frag) >= 12:
            for i, l in enumerate(lines, 1):
                if frag in l:
                    return True, i
    return False, None


def _common_suffix_len(a: str, b: str) -> int:
    """路径的公共**尾部**段数。用于判断"挪到哪去了"。"""
    pa, pb = a.split("/")[::-1], b.split("/")[::-1]
    n = 0
    for x, y in zip(pa, pb):
        if x == y:
            n += 1
        else:
            break
    return n


def search_issues(repo: str, keyword: str, tok: str, per_page: int = 5) -> list[dict]:
    """在仓库 issue 里搜关键词（查重用）。★ 只作**参考信号**，不当作结论。"""
    if not keyword or len(keyword) < 8:
        return []
    q = urllib.parse.quote(f"repo:{repo} {keyword}")
    code, body = _get(f"{API}/search/issues?q={q}&per_page={per_page}", tok=tok)
    if code != 200:
        return [{"_err": f"http{code}"}]
    try:
        items = json.loads(body).get("items", [])
    except Exception:
        return []
    return [{"number": it.get("number"), "state": it.get("state"),
             "title": (it.get("title") or "")[:110],
             "url": it.get("html_url")} for it in items]


def check_one(project: str, rel_file: str, snippet: str, cfg: dict, tok: str) -> dict:
    repo = repo_for(project, cfg)          # ★ 回退 targets*.yml，别只认手工那 3 条
    pkg = (cfg.get("packages") or {}).get(project)
    out: dict = {"repo": repo, "package": pkg, "checked_at": time.strftime("%Y-%m-%d")}
    if not repo:
        # ★ 明确标成"没查成"，绝不许让它看起来像"查过了、没报过"
        out["status"] = "no_repo"
        out["error"] = f"没配 {project} 的仓库坐标（upstream_repos.yml 与 targets*.yml 都没找到）"
        return out
    out["status"] = "ok"

    # ① default_branch + 是否归档
    code, body = _get(f"{API}/repos/{repo}", tok=tok)
    if code != 200:
        out["error"] = f"取仓库信息失败 http{code}"
        return out
    info = json.loads(body)
    br = info.get("default_branch", "main")
    out["default_branch"] = br
    out["archived"] = bool(info.get("archived"))
    out["pushed_at"] = info.get("pushed_at")

    # 分支 HEAD sha
    code, body = _get(f"{API}/repos/{repo}/branches/{br}", tok=tok)
    out["head_sha"] = json.loads(body).get("commit", {}).get("sha") if code == 200 else None

    # ② 特征串定位（不用行号）。★ 404 不代表"删了"——先看文件是不是被挪走了
    st, content = fetch_file(repo, rel_file, br, tok)
    out["file_fetch"] = st
    if st not in ("ok", "cached"):
        base = rel_file.split("/")[-1]
        cands = [p for p in repo_tree(repo, br, tok) if p.split("/")[-1] == base]
        out["path_candidates"] = cands[:6]
        if cands:
            # ★ 按"与原路径的公共尾段最长"选，别按路径长短选
            #   （按长短选会把 src/sample-toolkit/core/llm/base.py 当成 base.py 的新位置，错）
            newp = sorted(cands, key=lambda p: (-_common_suffix_len(rel_file, p), len(p)))[0]
            out["path_now"] = newp
            st2, content2 = fetch_file(repo, newp, br, tok)
            out["file_fetch"] = f"{st}→改查 {newp}:{st2}"
            st, content = st2, content2
    if st in ("ok", "cached") or "改查" in str(out.get("file_fetch", "")):
        present, hit = _locate(content, snippet)
        out["still_present"] = present
        out["line_now"] = hit
        out["file_lines_now"] = len(content.splitlines())
        out["path_present"] = out.get("path_now") or rel_file
    else:
        out["still_present"] = None
        out["file_removed"] = True
        out["file_fetch_err"] = str(content)[:160]

    # ③ 已公开的安全公告（公开端点，不需要特殊权限）
    if pkg:
        code, body = _get(f"{API}/advisories?ecosystem=pip&affects={pkg}&per_page=20", tok=tok)
        if code == 200:
            adv = json.loads(body)
            out["advisories"] = [{"ghsa": a.get("ghsa_id"), "sev": a.get("severity"),
                                  "summary": (a.get("summary") or "")[:100],
                                  "url": a.get("html_url")} for a in adv]
        else:
            out["advisories_err"] = f"http{code}"

    # ④ 仓库 issue 查重
    # ★ 教训（sample-toolkit）：只拿【文件干名】当关键词会漏——sample-toolkit 那条 RCE 的文件叫
    #   `base.py`（stem="base"，长度<8 直接跳过），而真报告 upstream issue 的标题走的是
    #   "sql injection … unsafe exec() on LLM output"。→ 改成**多关键词**，用
    #   (a) 特征串里辨识度最高的函数名/调用名 (b) 文件干名（够长才用），各搜一次并合并去重。
    kws: list[str] = []
    snippet_s = fd_snippet_tokens(snippet)
    if snippet_s:
        kws.append(snippet_s)
    # ★ 单词关键词在 GitHub issue 搜索里经常 0 命中（实测 kw='exec'→[]，但
    #   'code execution'→upstream issue/#1078）。→ 再按 sink 形态补一条【类别短语】。
    phrase = fd_snippet_phrase(snippet)
    if phrase:
        kws.append(phrase)
    stem = rel_file.split("/")[-1].replace(".py", "")
    if len(stem) >= 8:
        kws.append(stem)
    out["issue_keywords"] = kws
    merged: dict[int, dict] = {}
    for kw in kws:
        for h in search_issues(repo, kw, tok):
            n = h.get("number")
            if n and n not in merged:
                merged[n] = {**h, "_kw": kw}
    out["issue_hits"] = list(merged.values())
    return out


_STOP_TOKENS = {
    "self", "return", "import", "from", "def", "class", "print", "str", "int",
    "list", "dict", "None", "True", "False", "args", "kwargs", "value", "data",
    "type", "result", "name", "code", "text", "file", "path", "len", "open",
    # 通用接收者/module 名——拿去搜 issue 全是噪声
    "requests", "response", "session", "client", "conn", "cursor", "obj", "item",
    "get", "post", "put", "send", "load", "loads", "dumps", "run", "call",
    "match", "group", "search", "find", "format", "join", "split", "append",
}


def fd_snippet_tokens(snippet: str) -> str | None:
    """从特征串里挑一个**有辨识度**的词做 issue 搜索关键词。

    优先取【属性调用名】(`.foo(`) > 【裸函数名】(foo() > def foo()；
    过滤掉通用接收者/module 名与无辨识度的词。`exec`/`eval` 保留（它们正是
    issue 标题里会出现的词）。找不到返回 None。
    """
    if not snippet:
        return None
    # 优先：属性调用 .foo(   —— 比裸名更有辨识度（如 get_plotly_figure / run_sql）
    for nm in re.findall(r"\.([A-Za-z_]\w{3,})\s*\(", snippet):
        if nm.lower() not in _STOP_TOKENS:
            return nm
    # 其次：裸函数调用 foo(
    for nm in re.findall(r"(?<![\w.])([A-Za-z_]\w{3,})\s*\(", snippet):
        if nm.lower() not in _STOP_TOKENS:
            return nm
    # 退一步：行内最长的一个标识符（长度 ≥ 8 才用，避免噪声）
    ids = re.findall(r"[A-Za-z_]\w{7,}", snippet)
    if ids:
        return max(ids, key=len)
    return None


# sink 形态 → GitHub issue 搜索里常见的**漏洞类别短语**（单词搜不到，短语能）
_SINK_PHRASES = [
    (re.compile(r"(?<![\w.])(exec|eval)\s*\("), "code execution"),
    (re.compile(r"\b(pickle|dill|cPickle|marshal)\.loads?\s*\("), "deserialization"),
    (re.compile(r"\byaml\.load\s*\("), "yaml deserialization"),
    (re.compile(r"subprocess\.(run|Popen|call|check_output|check_call)|os\.(system|popen)"), "command injection"),
    (re.compile(r"\.execute\s*\(|\bexecute\s*\("), "sql injection"),
    (re.compile(r"\.(query|executemany|raw)\s*\([^)]*\bsql\b|conn\.query\s*\(|\brun_sql\s*\("), "sql injection"),
    (re.compile(r"\.read_text|open\s*\("), "path traversal"),
    (re.compile(r"\.(post|get|request)\s*\("), "ssrf"),
]


def fd_snippet_phrase(snippet: str) -> str | None:
    """由 sink 形态给一条**漏洞类别短语**（如 'code execution'/'sql injection'）。"""
    for pat, phrase in _SINK_PHRASES:
        if pat.search(snippet or ""):
            return phrase
    return None


def run_round_dir(rd: Path, on_log=print, only_verdict: str = "vuln") -> dict:
    """★ C1：把一个轮次的**要报出去的候选**跑一遍上游核实，写 `<rd>/upstream.json`。

    ★ 为什么要有这个函数（而不是让调用方各写一遍）：`app/check_upstream.py` 早就这么做，
      但 `run_round.py` **从来没调过它** → 结果"上游查了没查"全靠记不记得手动跑
      。
      → **单一实现**：`app/check_upstream.py` 与 `app/run_round.py` 都调本函数。
      ★ 从 `findings.tsv` 读（不接收内存对象），保证"报告的输入"和"核实的输入"是**同一份**。

    只查 `only_verdict`（默认 vuln）—— 其余候选不值得花配额。
    """
    import csv

    rd = Path(rd)
    tsv = rd / "findings.tsv"
    if not tsv.exists():
        on_log(f"  [upstream] 找不到 {tsv}，跳过")
        return {}
    rows = list(csv.DictReader(open(tsv, encoding="utf-8-sig"), delimiter="\t"))
    reps = [r for r in rows if (not only_verdict) or (r.get("ai_verdict") == only_verdict)]
    if not reps:
        on_log(f"  [upstream] 本轮没有 {only_verdict} 候选，无需核实")
        (rd / "upstream.json").write_text(
            json.dumps({"_meta": {"skipped": f"no {only_verdict} candidates",
                                  "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}},
                       ensure_ascii=False, indent=1), encoding="utf-8")
        return {}
    on_log(f"  [upstream] 核实 {len(reps)} 条（只查会报出去的）…")
    res = run(rd, reps, on_log=on_log)
    (rd / "upstream.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    ok = sum(1 for v in res.values() if v.get("still_present") is True)
    gone = sum(1 for v in res.values() if v.get("still_present") is False)
    arch = sum(1 for v in res.values() if v.get("archived"))
    # ★★ 必须把"没查成"单列 —— 否则 0/0 看起来像"查过了，没人报过"
    norepo = sum(1 for v in res.values() if v.get("error"))
    on_log(f"  [upstream] 上游仍存在 {ok} ｜ 上游已找不到 {gone} ｜ 仓库已归档 {arch} ｜ "
           f"★★ 没查成 {norepo}"
           + ("（★ 这 {0} 条**不许**当「未报」用）".format(norepo) if norepo else "")
           + " → upstream.json")
    return res


def run(rd: Path, findings: list[dict], on_log=print) -> dict:
    """findings = [{'project','file','snippet','fingerprint'}, ...]"""
    cfg = load_cfg()
    tok = _token()
    res: dict = {}
    seen_repo: dict = {}
    for fd in findings:
        fp = fd["fingerprint"]
        proj = fd["project"]
        try:
            r = check_one(proj, fd["file"], fd.get("snippet", ""), cfg, tok)
        except SystemExit:
            raise
        except Exception as e:
            r = {"error": f"{type(e).__name__}: {e}"}
        # 同仓库的信息（归档/默认分支）复用打印
        key = (proj, r.get("repo"))
        if key not in seen_repo:
            seen_repo[key] = r
            if r.get("error"):
                # ★★ 没查成必须**出声**，而且不许和"查过了、上游没这文件"混为一谈
                on_log(f"  [{proj}] ★★ 没查成：{r['error']}")
            else:
                flag = "★ 已归档" if r.get("archived") else "未归档"
                on_log(f"  [{proj}] {r.get('repo')} default_branch={r.get('default_branch')} "
                       f"{flag} pushed_at={r.get('pushed_at')}")
        if r.get("error"):
            continue                      # ★ 没查成的不进入下面的"仍在/已不存在"判断
        if r.get("still_present") is True:
            loc = r.get("path_present", fd["file"])
            moved = "" if loc == fd["file"] else f"  ★ 文件已挪到 `{loc}`"
            on_log(f"    {fd['file']}: 上游仍在（现在第 {r.get('line_now')} 行）{moved}")
        elif r.get("still_present") is False:
            where = r.get("path_present") or r.get("path_now") or fd["file"]
            on_log(f"    {fd['file']}: ★ 上游找不到该处（查了 {where}）")
        else:
            on_log(f"    {fd['file']}: ★ 上游文件已不存在"
                   f"（同名文件候选 {r.get('path_candidates', [])[:2]}）")
        if r.get("advisories"):
            on_log(f"    ★ 该包有 {len(r['advisories'])} 条公开公告")
        res[fp] = r
    return res
