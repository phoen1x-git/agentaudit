# -*- coding: utf-8 -*-
"""★★★ 第 9 条判据：「同函数内两种写法并存」

═══ 为什么这条信号最强 ═══
今天挖到的 5 个漏洞里，有 2 个最强的证据不是「分析出来的」，
而是 **★ 作者自己示范了正确写法，就在隔壁几行**：

```python
# SampleAgentX database_postgresql.py   ★ 同一个函数
:896  cur.execute(f"SELECT COUNT(*) ... FROM {collection_name}")   ← f-string 拼接
:898  cur.execute("... WHERE table_name = %s", (collection_name,))  ← 参数化

# SampleHub azure.py   ★ 同一个文件
:212  result_dict = eval(cleaned_buffer)                      ← eval
:578  content_as_list = ast.literal_eval(message["content"])  ← literal_eval
```

★★★ **它不需要「理解代码」就能定位**：
 不用判断输入来自外部、不用判断有没有绕过、不用判断作者意图 ——
 ★ 只要**两种等价写法出现在同一个函数里**，弱的那处就是嫌疑。

★ 这是**唯一一类「零误报信号」**：两处写法功能等价时，
  写错的那处**在语义上一定是错的**。

═══ 为什么它比 LLM 判定更适合做判据 ═══
LLM 判据要花钱、有随机性、会「太松」或「太紧」。
★ 这条判据是**纯语法模式匹配**：
  扫一遍文件，确定性的，零成本，可复现。

═══ 要扫的模式对 ═══
1. eval↔ literal_eval  /  exec↔ literal_eval
2. execute(f"...")↔ execute("...", params)     SQL 拼接 vs 参数化
3. shell=True vs shell=False                    同一文件里混用
4. `os.path.join(base, user_input)` vs `basename` 防穿越
5. verify=False（跳过证书校验）vs 有校验
6. `yaml.load` vs `yaml.safe_load`（这个已经在 EXEC_FUNCS 里了）
"""
import ast
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import recheck

POOL = os.path.join(HERE, "..", "data", "target_pool")
OUT = os.path.join(POOL, "criterion9_duality.json")


# ══════════════════════════════════════════════════════════════════
# ★ 每一对 = 「等价的两条路」，强弱并存 → 弱的可疑
# ══════════════════════════════════════════════════════════════════
#★ 用 unparse 后的文本匹配，避开源码格式差异
DUALITY_PAIRS = [
    # (类别, 强写法标记, 弱写法标记, 说明)
    ("eval_safe", r"\bliteral_eval\s*\(", r"(?<!literal_)\beval\s*\(",
     "literal_eval（安全）vs eval（可执行任意代码）"),
    ("exec_safe", r"\bast\.parse\s*\(", r"(?<!ast\.)\bexec\s*\(",
     "ast.parse+compile（安全）vs exec"),
    ("sql_safe", r"execute\s*\(\s*f?[\"'][^\"']*%s",
     r"execute\s*\(\s*f[\"']",
     "参数化查询 vs f-string 拼接"),
    ("sql_param", r"execute\s*\([^,]+,\s*\(", r"execute\s*\(\s*f[\"']",
     "execute(sql, params) vs execute(f-string)"),
    ("shell_on", r"shell\s*=\s*False", r"shell\s*=\s*True",
     "shell=False（安全）vs shell=True"),
    ("tls_verify_off", r"verify\s*=\s*True|CERT_REQUIRED|ssl_context",
     r"verify\s*=\s*False|CERT_NONE",
     "证书校验开 vs 关"),
    ("path_join", r"basename\s*\(|os\.path\.basename",
     r"os\.path\.join\s*\([^)]*\b(user|input|name|filename)\b",
     "basename 清洗 vs 直接 join 用户输入"),
    ("pickle", r"json\.loads?\s*\(", r"\bpickle\.loads?\s*\(",
     "json.loads vs pickle.loads"),
    ("yaml", r"yaml\.safe_load", r"yaml\.(unsafe_)?load\s*\(",
     "yaml.safe_load vs yaml.load"),
]

RX_STRONG = [(c, re.compile(s, re.I), re.compile(w, re.I), d)
             for c, s, w, d in DUALITY_PAIRS]


def scan_file(path, src):
    try:
        tree = ast.parse(src)
    except Exception:
        # ★ 语法错的文件也要扫（用行级正则），别因为解析失败丢掉
        return scan_lines(path, src, None)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        a = node.lineno
        b = getattr(node, "end_lineno", a) or a
        try:
            body = ast.unparse(node)
        except Exception:
            continue
        lines = body.splitlines()
        for cat, srx, wrx, desc in RX_STRONG:
            s_hit = [i for i, l in enumerate(lines, a) if srx.search(l)]
            w_hit = [i for i, l in enumerate(lines, a) if wrx.search(l)]
            if not w_hit:
                continue
            if not s_hit:
                # ★ 没有强写法 → 这是「全项目都没防护」，属另一个判据的事
                continue
            out.append({
                "cat": cat, "desc": desc, "func": node.name,
                "start": a, "end": b,
                "weak_at": w_hit[:4], "strong_at": s_hit[:4],
                "weak_code": [lines[i - a][:120] for i in w_hit[:3]],
                "strong_code": [lines[i - a][:120] for i in s_hit[:3]],
            })
    return out


def scan_lines(path, src, _):
    """语法错时的退路：按行窗口扫（±15 行内出现强弱两种写法）。"""
    out = []
    L = src.splitlines()
    for cat, srx, wrx, desc in RX_STRONG:
        for i, l in enumerate(L):
            if not wrx.search(l):
                continue
            a = max(0, i - 15)
            b = min(len(L), i + 16)
            s_hit = [j + 1 for j in range(a, b) if srx.search(L[j])]
            if s_hit:
                out.append({"cat": cat, "desc": desc, "func": "<module>",
                            "start": a + 1, "end": b,
                            "weak_at": [i + 1], "strong_at": s_hit[:4],
                            "weak_code": [l.strip()[:120]],
                            "strong_code": [L[j - 1].strip()[:120] for j in s_hit[:3]]})
    return out


TEST_PATH = re.compile(r"(^|/)(tests?|examples?|mocks?|samples?|fixtures?|"
                       r"benchmarks?|docs?)(/|$)", re.I)
TEST_NAME = re.compile(r"(^test_|_test\.py$|^conftest\.py$|^mock_|_mock\.py$)", re.I)


def main():
    recs = {}
    for line in open(os.path.join(POOL, "rc_v8_partial.jsonl"), encoding="utf-8"):
        line = line.strip()
        if line:
            d = json.loads(line)
            recs[d["repo"]] = d.get("branch") or "main"

    print("★ 第9 条判据：「同函数内两种写法并存」")
    print("  共 %d 对等价写法" % len(DUALITY_PAIRS))
    print()
    allhits = []
    for repo in sorted(recs):
        br = recs[repo]
        f, n, m = recheck.cache_files(repo, br)
        if not f:
            alt = "master" if br == "main" else "main"
            f, n, m = recheck.cache_files(repo, alt)
            if f:
                br = alt
        if not f:
            continue
        hits = []
        for path, src in f.items():
            if not path.endswith(".py"):
                continue
            p = path.replace("\\", "/")
            if TEST_PATH.search(p) or TEST_NAME.search(os.path.basename(p)):
                continue
            for h in scan_file(path, src):
                h["file"] = path
                h["_repo"] = repo
                h["_branch"] = br
                hits.append(h)
        if hits:
            allhits.extend(hits)
            print("  %-32s %d 处 %s"
                  % (repo.split("/")[-1][:32], len(hits),
                     dict(Counter(h["cat"] for h in hits))))

    json.dump(allhits, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print()
    print("=" * 74)
    print("★ 合计 %d 处" % len(allhits))
    print("=" * 74)
    for cat, c in Counter(h["cat"] for h in allhits).most_common():
        print("  %-16s %d" % (cat, c))
    print()
    print("★ 逐处明细（弱写法 / 强写法对照）：")
    for h in allhits:
        print("\n  %s | %s | %s::%s"
              % (h["_repo"].split("/")[-1][:20],
                 h["file"].split("/")[-1][:24], h["func"][:22], h["cat"]))
        print("    ★ 弱: %s" % (h["weak_code"][0] if h["weak_code"] else ""))
        print("    √ 强: %s" % (h["strong_code"][0] if h["strong_code"] else ""))
    print("\n结果写入 %s" % OUT)


if __name__ == "__main__":
    main()