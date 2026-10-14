"""A1 自用版入口 · 建「按版本建靶」的公告基准（`docs/117` 的口径）。

    python app/build_version_benchmark.py [--pool ...] [--max-mb 30] [--packages a,b]

★ 与 `advisory_benchmark.json` 的区别（关键）：
  老基准把「PyPI 包的公告」对到「GitHub 仓库快照」，于是必须**人工判断**
  "我们的快照在不在受影响区间"（`advisory_map.json`），而且踩过"公告区间写错"（CVE-2024-5826）。
  ★ 新基准：**公告说哪个版本受影响，就扫哪个版本的发包** —— 版本由公告直接给定，不需要人工判断。

  · `last_affected=X`  → 扫 X
  · `fixed=Y`          → 扫 Y 之前的那一版（按 PyPI 上传时间排序）
  · 只有 `introduced=0` → "到现在都没修" → 跳过（版本不可确定，不许猜）

★ 只收 `rce_like`（代码执行/命令注入/SQL 注入/路径穿越/反序列化）的公告 —— 那才是本工具的射程。
★ PyPI 元数据**落盘缓存**：大包（langchain / gradio / llama-index）的 JSON 有十几 MB，
  重跑一次要几分钟（踩过：第一次跑 9 分钟没出结果）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POOL = ROOT / "data" / "target_pool" / "advisory_pool.json"
OUT = ROOT / "data" / "target_pool" / "version_benchmark.json"
CACHE = ROOT / "data" / "target_pool" / "_pypi_cache"
_REPO = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")

# ★★ 「元包」问题：有些包的 PyPI 发包只是**空壳**（真正的代码在同仓库的另一个包里）。
#    实测：`langflow` 的包只有 0.01 MB（代码在 `lfx` / `langflow-base`），
#    `llama-index` 同理（代码在 `sample-index`），`pydantic-ai`（代码在 `pydantic-ai-slim`）。
#    扫空壳 = 什么都扫不到，而且是**假漏检**。→ 命中这些包时改扫别名包（版本号在 monorepo 里是同步的）。
PKG_ALIAS = {
    "langflow": "lfx",
    "llama-index": "sample-index",
    "pydantic-ai": "pydantic-ai-slim",
}
_META_MB = 0.3        # 发包小于此 → 疑似空壳，触发别名

# ★ 「相关性」判据的**第二版**：第一版只找 RCE/命令执行那几类词，
#   把 SSRF / 路径穿越 / 模板注入 / 反序列化全漏了 —— 而**它们都是本工具 sink 表里的东西**
#   （`requests.get/post` 就是 sink）。→ 这里放宽到"sink 相关"。
_SINK_WORDS = (
    "code execution", "remote code execution", "rce", "arbitrary code", "code injection",
    "command injection", "os command", "shell injection", "sandbox escape",
    "eval injection", "eval(", "sql injection", "sqli",
    "ssrf", "server-side request forgery", "server side request forgery",
    "path traversal", "directory traversal", "file write", "file read", "file deletion",
    "deserialization", "deserialisation", "template injection", "ssti",
)


def _relevant(it: dict) -> bool:
    s = (it.get("summary") or "").lower()
    return bool(it.get("rce_like")) or any(w in s for w in _SINK_WORDS)


def _is_pre(v: str) -> bool:
    """预发布版本（dev/rc/a/b/post）。选"fixed 之前那一版"时要排除，
    否则会挑到 1.11.0.dev16 这种（实测踩过）。"""
    return bool(re.search(r"(dev|rc|post|a|b)\d*$", v))


def _get(url: str, tries: int = 3, cache: bool = True) -> dict:
    CACHE.mkdir(parents=True, exist_ok=True)
    cp = CACHE / (hashlib.sha1(url.encode()).hexdigest()[:16] + ".json")
    if cache and cp.exists():
        try:
            return json.loads(cp.read_text(encoding="utf-8"))
        except Exception:           # noqa: BLE001
            pass
    last = None
    for i in range(tries):
        try:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with op.open(urllib.request.Request(url, headers={"User-Agent": "af-kernel"}),
                         timeout=40) as r:
                d = json.loads(r.read().decode("utf-8"))
            if cache:
                cp.write_text(json.dumps(d), encoding="utf-8")
            return d
        except Exception as e:      # noqa: BLE001
            last = e
            time.sleep(1.2 * (i + 1))
    raise last  # type: ignore[misc]


def _parse_ranges(ranges: list[str]) -> dict:
    out: dict = {"introduced": None, "last_affected": None, "fixed": None}
    for r in ranges:
        for part in str(r).split("/"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            k, v = k.strip(), v.strip()
            if k in out and v and v != "0":
                out[k] = v
    return out


def _release_times(pkg: str) -> list[tuple[str, datetime]]:
    d = _get(f"https://pypi.org/pypi/{pkg}/json")
    rel = []
    for ver, files in (d.get("releases") or {}).items():
        ts = None
        for f in files:
            ut = f.get("upload_time_iso_8601") or f.get("upload_time")
            if ut:
                try:
                    ts = datetime.fromisoformat(ut.replace("Z", "+00:00"))
                    break
                except Exception:   # noqa: BLE001
                    pass
        if ts is not None and files:
            rel.append((ver, ts))
    rel.sort(key=lambda x: x[1])
    return rel


def _artifact(pkg: str, ver: str) -> dict | None:
    try:
        d = _get(f"https://pypi.org/pypi/{pkg}/{ver}/json")
    except Exception:               # noqa: BLE001
        return None
    files = d.get("urls") or []
    order = {"sdist": 0, "bdist_wheel": 1}
    files = sorted(files, key=lambda f: order.get(f.get("packagetype"), 9))
    for f in files:
        if f.get("packagetype") in order and f.get("url"):
            return {"packagetype": f["packagetype"], "filename": f["filename"],
                    "url": f["url"], "mb": round((f.get("size") or 0) / 1024 / 1024, 2)}
    return None


def _repo_of(refs: list[str]) -> str | None:
    for u in refs or []:
        m = _REPO.match(str(u))
        if m and m.group(2) not in ("", "gist"):
            r = m.group(2)[:-4] if m.group(2).endswith(".git") else m.group(2)
            return f"{m.group(1)}/{r}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=str(POOL))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--max-mb", type=float, default=30.0)
    ap.add_argument("--packages", default="", help="只处理这些包（逗号分隔）")
    a = ap.parse_args()

    only = {s.strip() for s in a.packages.split(",") if s.strip()}
    pool = json.load(open(a.pool, encoding="utf-8"))["items"]
    _rank = {"exact": 2, "file": 1, "coarse": 0}
    best: dict[str, dict] = {}
    for it in pool:
        if not _relevant(it):
            continue
        if only and it["package"] not in only:
            continue
        cve = [x for x in it["aliases"] if str(x).startswith("CVE-")]
        key = cve[0] if cve else it["id"]
        cand = dict(it)
        cand["_key"] = key
        # ★ 同一漏洞常有 GHSA/PYSEC/CVE 多条记录，**定位精度**取最好的那条
        #   （只判 "exact 才替换" 会把 file 级的漏掉，实测第一版就漏了大批）
        if key not in best or _rank[cand["precision"]] > _rank[best[key]["precision"]]:
            best[key] = cand

    rl_cache: dict[str, list] = {}
    items = []
    for n, (key, it) in enumerate(sorted(best.items()), 1):
        pkg = it["package"]
        if pkg not in rl_cache:
            print(f"[{n}/{len(best)}] {pkg} …", flush=True)
            try:
                rl_cache[pkg] = _release_times(pkg)
            except Exception as e:  # noqa: BLE001
                print(f"    !! 取版本列表失败 {type(e).__name__}: {str(e)[:60]}")
                rl_cache[pkg] = []
        rel = rl_cache[pkg]
        if not rel:
            continue
        r = _parse_ranges(it["affected_ranges"])
        ver, how = None, ""
        if r["last_affected"]:
            ver, how = r["last_affected"], "last_affected"
        elif r["fixed"]:
            fx = [t for v, t in rel if v == r["fixed"]]
            if fx:
                prev = [v for v, t in rel if t < fx[0] and not _is_pre(v)]
                ver, how = (prev[-1], f"before-fixed({r['fixed']})") if prev else (None, "")
        if ver is None:
            continue
        art = _artifact(pkg, ver)
        if not art:
            continue
        scan_pkg, scan_ver = pkg, ver
        # ★ 空壳包 → 换别名包同版本再取一次
        if art["mb"] < _META_MB and pkg in PKG_ALIAS:
            alt = PKG_ALIAS[pkg]
            alt_art = _artifact(alt, ver)
            if alt_art and alt_art["mb"] > art["mb"]:
                print(f"    ~ {pkg}=={ver} 是空壳({art['mb']}MB) → 改扫 {alt}=={ver} "
                      f"({alt_art['mb']}MB)", flush=True)
                scan_pkg, art = alt, alt_art
        items.append({
            "key": key, "ids": [it["id"]] + [x for x in it["aliases"]],
            "package": pkg, "version": ver, "version_rule": how,
            "scan_package": scan_pkg, "scan_version": scan_ver,
            "metapackage": scan_pkg != pkg,
            "precision": it["precision"], "target_file": it.get("target_file"),
            "target_function": it.get("target_function"),
            "repo": _repo_of(it.get("refs")),
            "summary": it.get("summary"), "severity": it.get("severity"),
            "affected_ranges": it.get("affected_ranges"),
            "artifact": art, "size_mb": art["mb"],
            "in_size_budget": art["mb"] <= a.max_mb,
        })

    items.sort(key=lambda x: (not x["in_size_budget"], x["package"], x["version"]))
    doc = {"_meta": {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "source": "OSV.dev + PyPI", "n": len(items),
                     "n_with_location": sum(1 for i in items
                                            if i["target_file"] or i["target_function"]),
                     "max_mb": a.max_mb,
                     "rule": "公告点名哪个版本受影响就扫哪个版本（last_affected / before-fixed）"},
           "items": items}
    Path(a.out).write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"\n{len(items)} 条（有代码定位 {doc['_meta']['n_with_location']} 条）")
    for it in items:
        mark = "OK " if it["in_size_budget"] else "大 "
        sp = it["scan_package"]
        alias = f" (→{sp})" if it["metapackage"] else ""
        print(f"  [{mark}] {it['package']:20} =={it['version']:<12}{alias:16} "
              f"{it['size_mb']:6.2f}MB [{it['precision']:6}] "
              f"{it['target_function'] or '-'}() @ {it['target_file'] or '-'}")
    print(f"\n→ {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
