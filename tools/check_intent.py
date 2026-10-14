# -*- coding: utf-8 -*-
"""
核实 inconsistent_auth 的命中：这是真漏洞，还是项目自己声明的公开接口？

★ 为什么要这个工具：
  `inconsistent_auth` 报「同文件里有的端点有鉴权、有的没有」，
  但它**不知道项目的意图**。实测发现有的项目会写
  「鉴权契约测试」，明确声明某些端点**就是公开的**
  （如 sample-cli-app 的 `assert_auth_contract(router, public={("GET","/templates/{id}")})`）。
  → 规则推测意图，项目测试陈述意图。**冲突时以项目自己的声明为准。**

三步：
  1. 扫描被测项目的测试代码，找「公开端点声明」模式
     （assert_auth_contract / public= / PUBLIC_ROUTES / @public 等）
  2. 把声明的公开路径与规则命中做交集
  3. 交集里的 = 已声明公开（很可能是误报）；不在交集的 = 需人工核实
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(ROOT, "data", "target_pool")
CACHE = os.path.join(POOL, "_src_cache")

# 项目自己声明「公开端点」的常见写法
DECL_PATTERNS = [
    re.compile(r"assert_auth_contract\s*\(", re.M),
    re.compile(r"\bpublic\s*=\s*[\{\(\[]", re.M),          # public={...} / public=[...]
    re.compile(r"\bPUBLIC_ROUTES\b", re.M),
    re.compile(r"\bpublic_paths\b", re.M),
    re.compile(r"\bOPEN_ENDPOINTS\b", re.M),
    re.compile(r"\bANONYMOUS_ROUTES\b", re.M),
    re.compile(r"@public\b"),
    re.compile(r"\bno_auth\b.*=.*[\{\(\[]", re.M),
    re.compile(r"\brequires_auth\s*=\s*False\b", re.M),
]

# 判断一个文件是不是「测试/契约声明」文件
# ★ 注意：缓存文件名里路径分隔符被换成了 **双下划线**（`src_tests_api_content`），
#   所以分隔符必须写成 `/|__|_` —— 只写 `/|_` 会漏掉大批测试文件，
#   导致「明明有声明却报未找到」。这个坑我踩过一次。
TEST_HINT = re.compile(
    r"(^|[/_])(tests?|testing|spec|specs|conftest)(/|__|_)"
    r"|_test\.py|test_[^/]*\.py|contract",
    re.I)


def slug(repo):
    """缓存文件名的前缀：f__<owner>_<repo>__

    ★ 命名规则（实测确认，别再猜）：
        `f__` + owner + `_` + repo + `__` + 路径
        - 路径里的 `/` 全部换成 `_`
        - **owner/repo 里的连字符原样保留**（`sample-org_sample-cli-app`）
      所以这里只把 `/` 换成 `_`，**不能连字符一起换** ——
      换了会一个文件都匹配不上，而且表现为「未找到声明」这种
      看起来像"项目没写声明"的假象。
    """
    return repo.strip("/").replace("/", "_").lower()


def cache_paths(repo):
    """该仓库在缓存里的所有文件路径"""
    key = slug(repo)
    out = []
    for dp, dn, fn in os.walk(CACHE):
        for x in fn:
            if key in x.lower():
                out.append(os.path.join(dp, x))
    return out


def find_declarations(repo):
    """在测试代码里找公开端点声明"""
    hits = []
    files = cache_paths(repo)
    for p in files:
        base = os.path.basename(p)
        if not TEST_HINT.search(base.replace("f__", "/")):
            continue
        if os.path.getsize(p) == 0:
            continue
        try:
            txt = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        pats = [pt.pattern for pt in DECL_PATTERNS if pt.search(txt)]
        if pats:
            # 抓出声明的路径字面量
            paths = set(re.findall(r'["\'](/[A-Za-z0-9_{}\-/.]*)["\']', txt))
            hits.append({
                "file": base[22:] if base.startswith("f__") else base,
                "patterns": pats,
                "paths": sorted(paths)[:40],
            })
    return hits


def load_results():
    """合并所有批次，同 repo 取覆盖率最高的那条"""
    best = {}
    for tag in ("night", "refill", "refill2", "lowcov"):
        fp = os.path.join(POOL, "%s_result.jsonl" % tag)
        if not os.path.exists(fp):
            continue
        for line in open(fp, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            n = r.get("repo")
            c = r.get("coverage")
            if not n:
                continue
            if n not in best or (isinstance(c, (int, float))
                                 and c > best[n].get("coverage", 0)):
                r["_src"] = tag
                best[n] = r
    return best


def main():
    best = load_results()
    targets = [n for n in sorted(best)
               if (best[n].get("cells") or {}).get("inconsistent_auth", {})
               .get("tag") == "positive"]

    print("=" * 74)
    print("inconsistent_auth 命中 %d 个项目 —— 逐个查项目自己有没有声明公开" % len(targets))
    print("=" * 74)

    need_manual, declared_public = [], []
    for repo in targets:
        cov = best[repo].get("coverage") or 0
        decl = find_declarations(repo)
        n = (best[repo]["cells"]["inconsistent_auth"] or {}).get("n", 0)
        print()
        print("● %s   cov=%.0f%%  规则命中 %s 处" % (repo, cov * 100, n))
        if not decl:
            print("   未找到公开端点声明 → **需人工核实**")
            need_manual.append(repo)
            continue
        for d in decl[:3]:
            print("   声明文件: %s" % d["file"])
            print("     模式: %s" % ", ".join(d["patterns"][:4]))
            if d["paths"]:
                print("     声明的路径: %s" % ", ".join(d["paths"][:10]))
        declared_public.append(repo)

    print()
    print("=" * 74)
    print("汇总：%d 个项目" % len(targets))
    print("  找到公开声明 → 规则命中很可能是误报 : %d" % len(declared_public))
    for r in declared_public:
        print("      %s" % r)
    print("  无声明 → 仍需人工核实                : %d" % len(need_manual))
    for r in need_manual:
        print("      %s" % r)
    print()
    print("★ 规则不能知道项目意图；有测试/契约声明时以声明为准。")
    print("★ 没有声明也不等于有洞 —— 先看服务层有没有归属校验，再定性。")


if __name__ == "__main__":
    sys.exit(main())
