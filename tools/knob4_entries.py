# -*- coding: utf-8 -*-
"""★★★ 旋钮四：入口清单加长

论文原文（`论文框架内的五个旋钮.md` 第 47-60 行）
──────────────────────────────────────────────────
「论文把**用户直接打进对话框的那句话**当作唯一的起点。
  但 Agent 的入口其实不止一个。它读到的内容有好几个来源：
  · 用户**上传的文件**里的内容
  · 它**自己去抓的网页**
  · 它**从知识库里检索回来**的段落
  · 它调用工具之后，**工具返回给它**的结果
  从污点分析的角度看，**这些东西全都是「墨水」，全都可以是入口**，
  只是论文没把它们算进去——因为论文要控制变量，先把最简单的那一个跑通。
  ★ 多标几个入口点，就多覆盖一大片攻击面。」

═══ 现有清单的真实状态 ═══
`ast_criteria._REQ_PARAM` 只认 10 个名字：
    request / http_request / req / request_obj / raw_request /
    starlette_request / fastapi_request / scoped_request / req_obj

★★ **这批项目全是 FastAPI/Flask，主流入口根本不是 `request` 形参**：
    · `payload: dict = Body(...)`        ← FastAPI 的真正入口
    · `data: ChatRequest`                ← pydantic 模型入参
    · `req: AskRequest`
    · `question: str`  /  `message: str` ← 对话框输入本身
★ 所以旋钮四对这批项目的增益应该**特别大** —— 因为它补的就是「真实存在的入口」。

═══ 这一版做什么 ═══
Step 1  建五类入口清单（HTTP 之外的四种 + 原本的 HTTP）
Step 2  在同一批 30 个项目上扫，看新增多少
Step 3  ★ 关键是判「**这条入口的外部数据能不能到达危险出口**」——
        这才是污点分析，★ 不是「有个入参就算入口」
"""
import io
import json
import os
import re
import sys
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ast
import llm_client as LC
import llm_judge as J
import recheck

POOL = J.POOL
OUT = os.path.join(POOL, "knob4_entries.json")
OUT2 = os.path.join(POOL, "knob4_verdict.json")

# ══════════════════════════════════════════════════════════════════
# ★ 五类入口 —— 论文点名的四种 + 原本的 HTTP 请求
# ══════════════════════════════════════════════════════════════════
ENTRY_KINDS = {
    # ① 原本就有：HTTP 请求对象（论文的唯一起点）
    "http_request": [
        r"^\s*(request|http_request|http_req|req|request_obj|request_object|"
        r"req_obj|raw_request|scoped_request|starlette_request|"
        r"fastapi_request|web_request|flask_request)\b",
    ],
    # ② ★ 用户上传的文件（论文第1 条）
    "file_upload": [
        r"\b(upload_file|uploaded_file|file_path|filename|attachment|"
        r"document|doc_file|pdf_file|upload)\b",
        r"\b(UploadFile|File\(|FileStorage|multipart)\b",
        r"\.filename\b|\.read\(\)\s*#?\s*upload",
    ],
    # ③ ★ Agent 自己抓的网页（论文第 2 条）
    "web_fetch": [
        r"\b(fetch_url|crawl|scrape|crawler|spider|browse|"
        r"read_url|get_page|html_content|page_content|raw_html)\b",
        r"\b(requests\.get|httpx\.get|urllib\.request\.urlopen|aiohttp.*get)\s*\(",
        r"\b(BeautifulSoup|bs4|html2text|trafilatura|readability)\b",
    ],
    # ★★ 4 ★ 从知识库检索回来的段落（论文第 3 条）——
    #    ★★ 这一条最重要，因为它**在旋钮二里已经被实证了**（MetaClaw 的
    #       retrieve_for_prompt 就是它），而且它是 Agent 的核心行为。
    "kb_retrieval": [
        r"\b(retrieve|retrieval|search_memories|recall|"
        r"semantic_search|vector_search|similarity_search|"
        r"search_documents|query_collection|embedding_search)\w*\s*\(",
        r"\b(Chroma|FAISS|Qdrant|Pinecone|Weaviate|Milvus|pgvector|"
        r"Elasticsearch|OpenSearch)\b",
        r"\b(top_k|top_n|limit)\s*=\s*\d+.*\b(query|question|text)\b",
    ],
    # ★ 5 ★ 工具返回值（论文第 4 条）
    #   ★★ 这一条最难静态判 —— 它是「函数返回值」，
    #      所以判据只能标出「这里有个工具结果可能被当数据用」。
    "tool_result": [
        r"\b(tool_result|tool_output|tool_response|function_response|"
        r"observation|action_result|step_result|tool_returns)\b",
        r"\b(execute_tool|call_tool|invoke_tool|run_tool|"
        r"call_function|invoke_function)\w*\s*\(",
        r"\bToolMessage|ToolResult|FunctionResult\b",
    ],
}

TEST_PATH = re.compile(r"(^|/)(tests?|examples?|mocks?|samples?|fixtures?|"
                       r"benchmarks?|docs?)(/|$)", re.I)
TEST_NAME = re.compile(r"(^test_|_test\.py$|^conftest\.py$|^mock_|_mock\.py$)", re.I)


def is_test_demo(path):
    p = path.replace("\\", "/")
    return bool(TEST_PATH.search(p) or TEST_NAME.search(os.path.basename(p)))


def scan_entry_functions(fmap):
    """★ 不扫「行」而是扫「端点/入口函数」——
    因为污点分析的入口是**参数**，不是某一行代码。"""
    import ast
    out = []
    for fp, src in fmap.items():
        if not fp.endswith(".py") or is_test_demo(fp):
            continue
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        # 端点装饰器
        ROUTE = re.compile(r"^(@|\w+\.)?\w*\.(get|post|put|delete|patch|route|websocket)\s*\(")
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_route = False
            for d in node.decorator_list:
                try:
                    if ROUTE.search(ast.unparse(d)[:40]):
                        is_route = True
                except Exception:
                    pass
            if not is_route:
                continue
            try:
                sig = ast.unparse(node.args)
            except Exception:
                continue
            try:
                body = "\n".join(ast.unparse(node).splitlines()[:60])
            except Exception:
                body = ""
            kinds = {}
            for kind, pats in ENTRY_KINDS.items():
                hit = []
                for pat in pats:
                    if re.search(pat, sig, re.I) or re.search(pat, body, re.I):
                        hit.append(pat[:26])
                if hit:
                    kinds[kind] = hit
            if kinds:
                out.append({
                    "file": fp, "line": node.lineno, "func": node.name,
                    "sig": sig[:200], "kinds": kinds,
                })
    return out


# ══════════════════════════════════════════════════════════════════
# Step 3：LLM 判「能不能到达危险出口」
# ══════════════════════════════════════════════════════════════════
RUBRIC_K4 = """你是一个 Agent 项目「污点入口」的判定员。

背景：我们在扩展污点分析的入口清单。原论文只把
「用户直接打进对话框的那句话」当唯一起点，
现在加了：上传的文件 / 抓的网页 / 知识库检索结果 / 工具返回值。

★ 你的任务**不是**判断「有没有漏洞」，而是判断三件事：

① ★ 这条入口**真的有外部数据**吗？
   · pydantic/Body 入参、`request.json()`、上传文件 → 真有
   · ★ 只有路径配置项（file_path="/etc/config"）→ 没有外部数据
   · 内部常量/枚举 → 没有

② ★ 这些外部数据**流到危险操作**了吗？
   危险操作 = 执行命令 / 拼 prompt 里的 system 指令 / 写文件 / 发外部请求 /
   送进 LLM 当指令
   ★★ **「进了 LLM 的 prompt」也算** —— 那就是间接的代码/指令执行面。

③ ★ 数据流闭合吗？（从入口能一路跟到②）

★★ 最容易误判的：
  · 看到 `filename: str` 就判「文件上传入口」→ ★ 只是路径字符串，
    要看有没有真的 `open()` / `UploadFile.read()`
  · 看到 `search(query)` 就判「知识库入口」→ 要看是不是真连了向量库
  · ★ 进了 prompt 但只是当「展示内容」→ 不是危险操作

输出 JSON：
{
  "has_external_data": "yes|no|unclear",
  "external_data_evidence": "一句话，引用具体代码",
  "reaches_danger": "yes|no|unclear",
  "danger_evidence": "一句话，引用具体危险操作",
  "flow_closed": "yes|no|unclear",
  "entry_kinds_valid": ["file_upload", "web_fetch", ...],
  "verdict": "real_taint|benign|needs_human",
  "severity": "none|low|medium|high",
  "confidence": 0.0-1.0,
  "one_line": "一句话结论"
}

判定尺度：
- real_taint  入口有真外部数据 **且** 流到危险操作 **且** 流闭合
- benign     至少一条不成立
- needs_human 代码片段不足
★ 信息不足就给 needs_human并降低 confidence，
  **不要为了给答案而把三条都答 yes**。"""


def main():
    step1_only = os.environ.get("K4_STEP") == "1"
    recs = J.load_recs()
    targets = sorted({v.get("_repo") for v in
                      json.load(open(os.path.join(POOL, "llm_verdict.json"),
                                   encoding="utf-8")).values()} - {None})

    print("★ 旋钮四 · 入口清单加长")
    print("  现有入口清单：_REQ_PARAM 只认 10 个名字（全是 request 类形参）")
    print("  新增入口：%s" % list(ENTRY_KINDS))
    print()
    print("%-34s %-8s %s" % ("项目", "端点数", "入口类型分布"))
    print("-" * 74)

    allres = []
    for repo in targets:
        rec = recs.get(repo)
        br = (rec.get("branch") if rec else None) or "main"
        fmap, _n, _m = recheck.cache_files(repo, br)
        if not fmap:
            alt = "master" if br == "main" else "main"
            fmap, _n, _m = recheck.cache_files(repo, alt)
            if fmap:
                br = alt
        if not fmap:
            continue
        hs = scan_entry_functions(fmap)
        if not hs:
            continue
        c = Counter(k for h in hs for k in h["kinds"])
        print("%-34s %-8d %s" % (repo.split("/")[-1][:34], len(hs), dict(c)))
        for h in hs:
            h["_repo"] = repo
            h["_branch"] = br
        allres.extend(hs)

    json.dump(allres, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print()
    print("=" * 74)
    print("★ Step 1 结果：端点总数 %d（含入口信号的）" % len(allres))
    print("=" * 74)
    c = Counter(k for h in allres for k in h["kinds"])
    for k, n in c.most_common():
        print("  %-16s %d" % (k, n))
    #★ 对比：只认 request 类形参的话能覆盖多少
    only_http = sum(1 for h in allres if "http_request" in h["kinds"])
    print()
    print("★ 只认原本的 request 类形参 → %d 个端点" % only_http)
    print("  扩到五类后→ %d 个端点（+%d）"
          % (len(allres), len(allres) - only_http))
    print("结果写入 %s" % OUT)

    if step1_only:
        print("\n（设 K4_STEP=2 才跑 Step 2，要花钱）")
        return

    # ---------- Step 2 ----------
    per_repo = int(os.environ.get("K4_PER_REPO", "6"))
    done = json.load(open(OUT2, encoding="utf-8")) if os.path.exists(OUT2) else {}
    print()
    print("=" * 74)
    print("★ Step 2：LLM 判「外部数据能不能到达危险出口」")
    print("=" * 74)
    cost0 = LC.USAGE.cny
    byrepo = {}
    for h in allres:
        byrepo.setdefault(h["_repo"], []).append(h)

    for repo in sorted(byrepo):
        hs = byrepo[repo]
        # ★ 优先挑「非 http_request」的（那才是旋钮四的增量）
        picked = [h for h in hs if "http_request" not in h["kinds"]] or hs
        picked = picked[:per_repo]
        fmap, _n, _m = recheck.cache_files(repo, hs[0]["_branch"])
        if not fmap:
            continue
        for h in picked:
            key = "%s|%s|%d" % (repo, h["file"], h["line"])
            if key in done:
                continue
            try:
                body = ast.unparse(
                    [n for n in ast.walk(ast.parse(fmap[h["file"]]))
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.lineno == h["line"]][0])
            except Exception:
                body = ""
            user = ("【项目】%s\n【端点】%s:%d  %s\n  签名：%s\n"
                    "  判据认为的入口类型：%s\n\n【函数完整源码】\n%s\n\n"
                    "请判断：这条入口的外部数据能不能到达危险操作？"
                    % (repo, h["file"], h["line"], h["func"], h["sig"],
                       json.dumps(h["kinds"], ensure_ascii=False),
                       "\n".join("  " + x[:110] for x in body.splitlines()[:60])))
            try:
                r = LC.ask_json(RUBRIC_K4, user, tag="knob4", max_tokens=3600)
            except Exception as e:
                print("  ★ %s 失败 %s" % (repo.split("/")[-1][:18], str(e)[:40]))
                continue
            r["_repo"] = repo
            r["_file"] = h["file"]
            r["_line"] = h["line"]
            r["_kinds"] = h["kinds"]
            r["_sig"] = h["sig"]
            done[key] = r
            json.dump(done, open(OUT2, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
            print("  %-22s %-26s %-12s %-7s %s"
                  % (repo.split("/")[-1][:22], h["func"][:26],
                     r.get("verdict"), r.get("severity"),
                     (r.get("one_line") or "")[:40]))

    print()
    print("判定 %d 处，花费 %.4f 元" % (len(done), LC.USAGE.cny - cost0))
    print("verdict:  %s" % dict(Counter(v.get("verdict")
                                        for v in done.values())))
    print("severity: %s" % dict(Counter(v.get("severity")
                                       for v in done.values())))


if __name__ == "__main__":
    main()