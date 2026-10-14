"""内核 · 目标「攻击面预检」

要解决的问题
------------
`docs/56` 的实战结论是「**库型项目没有对外端点，扫了也是 0**」，但它当时只能靠人读描述判断。
A1 第一批又验证了一遍：**描述里写着 web / api，不等于真有攻击面** ——
那一批 12 个目标里，好几个本质是"工具脚本集合"，扫出来 0 条 vuln。

本模块把那条经验做成**可执行的前检**：不看描述，直接读仓库的
  · **文件树** —— 有没有"执行原语"的痕迹（code_interpreter / executor / repl / sandbox / sql / browser）
  · **依赖清单** —— 有没有 LLM 客户端依赖、有没有 Web 层
  · **夹带代码比例** —— 有多少文件在 vendor/third_party/node_modules 下（这类副本会污染候选池，
    见 `docs/102`；夹带多的目标，后续 path-filter 的收益也大）

★ 它**不判断有没有漏洞**，只回答"这个目标值不值得建库去扫"。两次 API 调用/仓库，很便宜。

信号为什么这么定（都有依据，不是拍的）：
  · 「执行原语」= AgentFuzz 那套 sink 的必要条件。没有执行原语的仓库，sink 清单一条都不会命中。
  · 「LLM 依赖」= 这个项目**真的在调模型**。没有它，"LLM 产出 → 危险调用"这条链根本不存在。
  · 两个都要：只有 web 没有 LLM → 是普通 Web 应用（不在本项目射程内）；
    只有 LLM 没有执行原语 → 是个聊天壳子（sink 命中 0）。
"""
from __future__ import annotations

import re

from . import gh

# ---- 「执行原语」的路径信号（出现在文件路径里即计分）----
SURFACE_PATHS = {
    "code_interpreter": 5, "codeinterpreter": 5, "code_executor": 5, "codeexecutor": 5,
    "executor": 4, "sandbox": 4, "repl": 4, "interpreter": 3,
    "shell": 3, "terminal": 3, "subprocess": 3, "execution": 3,
    "sql": 3, "query_engine": 3, "database": 1,
    "browser": 2, "playwright": 2, "selenium": 2, "crawler": 2,
    "tool": 1, "tools": 1, "function_call": 3, "skill": 1,
}
# ---- 值得为它建库的依赖 ----
LLM_DEPS = {
    "openai", "langchain", "langchain-core", "langchain-community", "llama-index",
    "llamaindex", "llama_index", "pyautogen", "autogen", "crewai", "litellm",
    "anthropic", "google-generativeai", "google-genai", "dashscope", "zhipuai",
    "qianfan", "semantic-kernel", "haystack-ai", "dspy", "dspy-ai", "smolagents",
    "transformers", "vllm", "ollama", "openai-agents", "agentops", "phidata",
    "agno", "pydantic-ai", "browser-use", "composio", "mcp",
}
WEB_DEPS = {"fastapi", "flask", "django", "streamlit", "gradio", "aiohttp",
            "tornado", "uvicorn", "sanic", "bottle", "flet", "nicegui"}
# ---- 夹带代码的路径标记（这些目录下的文件不算项目自己的攻击面）----
VENDOR_MARKS = ("/vendor/", "/third_party/", "/thirdparty/", "/node_modules/",
                "/builtin_skills/", "/site-packages/", "/dist/", "/build/",
                "/miniconda", "/anaconda", "/.venv/", "/venv/")


def _dep_names(text: str) -> set[str]:
    """从 requirements / pyproject / setup 里粗提依赖名。不解析 TOML，抓名字足够。"""
    out = set()
    for raw in (text or "").splitlines():
        s = raw.strip().strip('",\'')
        if not s or s.startswith("#"):
            continue
        # requirements.txt: name==1.2 [extra]
        for sep in ("==", ">=", "<=", "~=", ">", "<", "[", ";", " ", "="):
            if sep in s:
                s = s.split(sep, 1)[0]
        s = s.strip().strip('",\'').lower()
        if s and all(c.isalnum() or c in "-_." for c in s):
            out.add(s)
    return out


def probe(repo: str, branch: str, tok: str | None = None) -> dict:
    """两次 API 调用：文件树 + 依赖清单。失败时返回 ok=False，不抛异常。"""
    r = {"repo": repo, "ok": False, "n_files": 0, "tree_bytes": 0, "surface": [],
         "surface_score": 0,
         "llm_deps": [], "web_deps": [], "vendor_ratio": 0.0, "tree_truncated": False}
    j = gh.get_json(f"{gh.API}/repos/{repo}/git/trees/{branch}?recursive=1", tok=tok)
    if not j or "tree" not in j:
        r["err"] = "tree"
        return r
    paths = [x["path"] for x in j.get("tree", []) if x.get("type") == "blob"]
    r["ok"] = True
    r["n_files"] = len(paths)
    r["tree_truncated"] = bool(j.get("truncated"))
    # ★★ 工作树总字节：`git/trees` 每条 blob 都带 size。
    #    这是**下载体积的准确代理** —— GitHub 的 `size` 字段含 .git 历史，实测能差 7 倍
    #    （sampleproj：size 16.7MB，真实 tarball 只有 2.3MB），拿它当门槛会大面积误杀。
    r["tree_bytes"] = sum(int(x.get("size") or 0) for x in j.get("tree", [])
                          if x.get("type") == "blob")
    low = [p.lower() for p in paths]
    hits = {}
    for key, w in SURFACE_PATHS.items():
        if any(key in p for p in low):
            hits[key] = w
    r["surface"] = sorted(hits, key=lambda k: -hits[k])
    r["surface_score"] = sum(hits.values())
    n_vendor = sum(1 for p in low if any(m in "/" + p for m in VENDOR_MARKS))
    r["vendor_ratio"] = round(n_vendor / len(paths), 3) if paths else 0.0

    # 依赖：pyproject 优先，其次 requirements
    deps: set[str] = set()
    for fn in ("pyproject.toml", "requirements.txt", "setup.py"):
        code, body = gh.get(f"{gh.API}/repos/{repo}/contents/{fn}?ref={branch}",
                            raw=True, tok=tok)
        if code == 200 and body:
            deps |= _dep_names(body)
        if len(deps) >= 5:
            break
    r["llm_deps"] = sorted(d for d in deps if d in LLM_DEPS)
    r["web_deps"] = sorted(d for d in deps if d in WEB_DEPS)
    r["n_deps"] = len(deps)
    return r


# ---- 「真的在跑模型产出的代码吗」—— ★ 必须读内容，不能只看名字 ----
# ★★ 依据（`docs/112` 补记 / `docs/113` §八）：关键词命中的是**文件名和类名**
#    （`shell_tool.py`、`class Executor`）。实测那 6 个"强信号"目标
#    （sampleproj / overmind / marginalia / cascadeflow / openosint / synapse-ai）
#    **实际产出 0 条 exec 类候选** —— 只靠名字会把它们当 Agent。
_EXEC_CALL = re.compile(r"(?<![\w.])exec[ \t]*\(|(?<![\w.])eval[ \t]*\(")
_EXECISH = ("code_exec", "executor", "sandbox", "interpreter", "repl")


def probe_exec_content(repo: str, branch: str, tok: str | None = None,
                       max_files: int = 6) -> dict:
    """读「像执行器」的那些文件**内容**，数真实的 `exec(` / `eval(` 出现。

    返回 `{ok, files, n_exec, samples}`。
    ★ 这是 `probe()` 的补充：`probe()` 只看文件名（便宜，1 次 API），
      本函数读内容（贵一些，N 次 API），用来**验证名字信号是真是假**。
    """
    out: dict = {"repo": repo, "ok": False, "files": [], "n_exec": 0, "samples": []}
    tok = tok or gh.token()
    t = gh.get_json(f"{gh.API}/repos/{repo}/git/trees/{branch}?recursive=1", tok=tok)
    if not t or "tree" not in t:
        return out
    cands = [x["path"] for x in t["tree"]
             if x.get("type") == "blob" and x["path"].endswith(".py")
             and any(k in x["path"].lower() for k in _EXECISH)]
    # 名字越像"真正的执行器"越靠前
    cands.sort(key=lambda p: (0 if any(k in p.lower() for k in
                                       ("code_exec", "executor", "sandbox", "interpreter"))
                              else 1, len(p)))
    out["ok"] = True
    for p in cands[:max_files]:
        code, body = gh.get(f"{gh.API}/repos/{repo}/contents/{p}?ref={branch}",
                            raw=True, tok=tok)
        if code != 200:
            continue
        out["files"].append(p)
        for i, line in enumerate(body.splitlines(), 1):
            if _EXEC_CALL.search(line):
                out["n_exec"] += 1
                if len(out["samples"]) < 5:
                    out["samples"].append(f"{p}:{i}  {line.strip()[:100]}")
    return out


def remote_source_bytes(repo: str, branch: str, tok: str | None = None) -> int | None:
    """下载体积的准确代理：`git/trees` 里所有 blob 的 size 之和。

    ★ 比 GitHub 的 `size` 字段可靠得多 —— 后者含 `.git` 历史，实测能差 7 倍。
    返回 None 表示 tree 被截断（超大树），此时调用方应回退到 `size` 字段。
    """
    j = gh.get_json(f"{gh.API}/repos/{repo}/git/trees/{branch}?recursive=1", tok=tok)
    if not j or "tree" not in j:
        return None
    if j.get("truncated"):
        return None
    return sum(int(x.get("size") or 0) for x in j["tree"] if x.get("type") == "blob")


def verdict(r: dict) -> tuple[bool, str]:
    """值不值得建库扫。★ 规则写死在这里，便于复盘与调参。"""
    if not r.get("ok"):
        return False, "探测失败"
    has_exec = r["surface_score"] >= 5
    has_llm = bool(r["llm_deps"])
    if not has_llm:
        return False, "★ 没有 LLM 客户端依赖（『LLM 产出→危险调用』这条链不存在）"
    if not has_exec:
        return False, f"★ 没有执行原语信号（surface={r['surface_score']}，{r['surface']}）"
    if r["vendor_ratio"] > 0.5:
        return False, f"★ 夹带代码占比过高（{r['vendor_ratio']:.0%}）"
    if r["n_files"] > 4000:
        return False, f"文件过多（{r['n_files']}），建库太慢"
    return True, f"exec={r['surface_score']} llm={r['llm_deps']} web={r['web_deps']}"
