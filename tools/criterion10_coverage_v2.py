# -*- coding: utf-8 -*-
"""★★★ crit10 v2：**同类防护**覆盖率（v1 太松，940 处全是噪声）

═══ v1 的问题 ═══
v1 只要「文件里有防护、当前函数没调」就报
→ 报出 940 处，全是噪声
★ **病根**：**不同函数的防护本来就不该通用**——
   `basename()`在 A 函数里用来清洗文件名，不代表 B 函数也需要它。

═══ v2 的收紧：防护必须和危险操作「同类」 ═══
```
★ 对应关系（只认「防的就是这一类」的）：
  pickle          ←→ SecurityVisitor / ast_node_visitor / allowlist
  eval/exec       ←→ literal_eval / SecurityVisitor
  sql_fstring     ←→ param_query（同一文件里别处用了参数化）
  subprocess      ←→ shell_false（别处关掉了 shell）
  dynamic_getattr ←→ allowlist
  unvalidated_header ←→ auth_dependency（★ 这个最严：别处挂了鉴权）
  yaml            ←→ safe_load
```
★ 这样报出来的才是「**同一类操作，作者在别处防了，这里没防**」。

═══ 第三层收紧 ═══
★ v1/v2 报的都是「文件级」证据。
★ **真正强的是「同一类防护在同一个类/模块的邻近函数里被用了」** ——
  那说明作者**在这个语境下**是有防护意识的，只是这一处漏了。
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
OUT = os.path.join(POOL, "criterion10_v2.json")

# ★★ 危险类型 →「能防它的同类防护」
DANGER_GUARD = {
    "pickle":          ["SecurityVisitor", "ast_node_visitor", "allowlist",
                        "literal_eval", "safe_load"],
    "eval":            ["literal_eval", "SecurityVisitor"],
    "exec":            ["literal_eval", "SecurityVisitor", "ast_node_visitor"],
    "yaml":            ["safe_load"],
    "sql_fstring":     ["param_query", "allowlist"],
    "subprocess":      ["shell_false", "allowlist"],
    "dynamic_getattr": ["allowlist"],
    "tls_off":         ["tls_verify"],
    "unvalidated_header": ["auth_dependency"],   # ★ 最严的一档
}

GUARD_CALLS = {
    "SecurityVisitor": r"SecurityVisitor\s*\(\s*\)\s*\.\s*visit\s*\(",
    "ast_node_visitor": r"\.generic_visit\s*\(|NodeVisitor\s*\(",
    "validate_input": r"(validate|verify|check|sanitize)_\w+\s*\(",
    "allowlist": r"(ALLOWLIST|ALLOWED|WHITELIST|PATTERNS|allow_list|whitelist|allowlist)\b",
    "path_contain": r"(is_relative_to|relative_to|commonpath|realpath|abspath)\s*\(",
    "basename": r"os\.path\.basename\s*\(|secure_filename\s*\(",
    "auth_dependency": r"Depends\s*\(|verify_token|require_auth|current_user",
    "param_query": r"(execute|executemany)\s*\([^,]+,\s*\(",
    "literal_eval": r"literal_eval\s*\(|ast\.parse\s*\(",
    "safe_load": r"yaml\.safe_load|json\.loads?\s*\(",
    "shell_false": r"shell\s*=\s*False",
    "tls_verify": r"verify\s*=\s*True|CERT_REQUIRED",
}

DANGER = {
    "pickle": r"\bpickle\.loads?\s*\(|\bcloudpickle\.loads?\s*\(",
    "eval": r"(?<!literal_)\beval\s*\(",
    "exec": r"(?<!ast\.)\bexec\s*\(",
    "yaml": r"yaml\.(unsafe_)?load\s*\(",
    "sql_fstring": r"execute\s*\(\s*f[\"']",
    "subprocess": r"(subprocess\.(run|call|Popen|check_output)|os\.system|os\.popen)",
    "dynamic_getattr": r"getattr\s*\(\s*\w+\s*,\s*\w+\s*\)",
    "tls_off": r"verify\s*=\s*False|CERT_NONE",
    "unvalidated_header": r"request\.headers\.get\s*\(",
}

RX_GUARD = {k: re.compile(v) for k, v in GUARD_CALLS.items()}
RX_DANGER = {k: re.compile(v) for k, v in DANGER.items()}

TEST_PATH = re.compile(r"(^|/)(tests?|examples?|mocks?|samples?|fixtures?|"
                       r"benchmarks?|docs?)(/|$)", re.I)
TEST_NAME = re.compile(r"(^test_|_test\.py$|^conftest\.py$|^mock_|_mock\.py$)", re.I)


def scan_file(path, src):
    try:
        tree = ast.parse(src)
    except Exception:
        return []
    funcs = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a, b = node.lineno, (getattr(node, "end_lineno", node.lineno)
                                 or node.lineno)
            try:
                body = ast.unparse(node)
            except Exception:
                continue
            funcs.append({"node": node, "name": node.name, "start": a,
                          "end": b, "body": body,
                          "guards": {k for k, rx in RX_GUARD.items()
                                     if rx.search(body)}})
    out = []
    for f in funcs:
        lines = f["body"].splitlines()
        for dk, rx in RX_DANGER.items():
            for i, l in enumerate(lines, f["start"]):
                if not rx.search(l):
                    continue
                # ★ 同类防护：当前函数调了吗？
                want = set(DANGER_GUARD.get(dk, []))
                in_func = f["guards"] & want
                if in_func:
                    continue                       # ★ 本函数有同类防护 → 不是嫌疑
                # ★ 同文件/同类的其他函数用了同类防护吗？
                others = [g["name"] for g in funcs
                          if g is not f and (g["guards"] & want)]
                # ★ 还要看模块级（函数外的代码）有没有用
                mod_guard = {k for k, rx in RX_GUARD.items()
                             if rx.search(src)} & want
                if not others and not mod_guard:
                    continue                       # ★ 全项目都没这类防护 → 不报
                out.append({
                    "file": path, "func": f["name"], "line": i,
                    "danger_kind": dk, "danger_code": l.strip()[:110],
                    "want_guards": sorted(want),
                    "★_used_elsewhere": sorted(set(others))[:5],
                    "★_guard_in_module": sorted(mod_guard),
                    "★_level": ("same_module" if mod_guard else "other_func"),
                })
                break                    # ★ 每类只报第一处，避免刷屏
    return out


def main():
    recs = {}
    for line in open(os.path.join(POOL, "rc_v8_partial.jsonl"), encoding="utf-8"):
        line = line.strip()
        if line:
            d = json.loads(line)
            recs[d["repo"]] = d.get("branch") or "main"

    print("★ crit10 v2：同类防护覆盖率（v1 是 940 处噪声）")
    print()
    allhits = []
    for repo in sorted(recs):
        br = recs[repo]
        f, n, m = recheck.cache_files(repo, br)
        if not f:
            alt = "master" if br == "main" else "main"
            f, n, m = recheck.cache_files(repo, alt)
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
                h["_repo"] = repo
                hits.append(h)
        if hits:
            allhits.extend(hits)
            print("  %-30s %d" % (repo.split("/")[-1][:30], len(hits)))

    json.dump(allhits, open(OUT, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print()
    print("=" * 78)
    print("★ 合计 %d 处（v1 是 940 → 噪声减少 %.0f%%）"
          % (len(allhits), 100.0 * (1 - len(allhits) / 940.0)))
    print("=" * 78)
    print("按危险类型：%s" % dict(Counter(h["danger_kind"] for h in allhits)))
    print("按证据强度：%s" % dict(Counter(h["★_level"] for h in allhits)))
    print()
    print("★★★ ★ 最强的一档（模块级就有同类防护，当前函数没调）：")
    strong = [h for h in allhits if h["★_level"] == "same_module"]
    print("    共 %d 处" % len(strong))
    for h in strong[:12]:
        print("  %-20s %-22s::%-16s %s"
              % (h["_repo"].split("/")[-1][:20],
                 h["file"].split("/")[-1][:22], h["func"][:16],
                 h["danger_kind"]))
        print("     危险: %s" % h["danger_code"][:88])
        print("     ★ 模块里有同类防护 %s，但这个函数没调"
              % ", ".join(h["★_guard_in_module"][:4]))
    print("\n结果写入 %s" % OUT)


if __name__ == "__main__":
    main()