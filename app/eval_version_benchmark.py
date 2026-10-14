"""A1 自用版入口 · 用「按版本建靶」的基准评测召回。

    python app/eval_version_benchmark.py out/round-pkg-20261010

★ 口径（写死，别事后改）：
  · 分母 = **本轮真扫过的（包,版本）** 里，公告给了代码定位（文件名）的条目
  · 命中 = findings 里该项目的某条，**文件 basename 与公告一致**（函数名对上更硬）
  · ★ 只按**文件名**匹配，不要求判定正确 —— 召回衡量的是"有没有把它捞出来给人看"
  · 公告没给文件名 → **不计入自动分母**，单列成"需人工映射"（不许静默当成漏检）
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BM = ROOT / "data" / "target_pool" / "version_benchmark.json"
PKG_SRC = ROOT.parent / "_targets" / "pkg"

# 单文件名太泛（base.py / service.py / types.py 一堆），所以**必须比对最后两段**：
# 公告给的是仓库路径（`src/backend/base/langflow/services/auth/service.py`），
# 发包里层级常少一层（`langflow/services/auth/service.py`）→ 用「末两段」当后缀最稳。
# ★ 踩过：只比 basename 会把 `lfx/services/mcp_composer/service.py` 当成
#   `.../services/auth/service.py` 的命中 —— **假命中**（凭空抬高召回）。
def _suffix2(target_file: str) -> str:
    parts = [p for p in target_file.split("/") if p and p not in (".", "..")]
    if not parts:
        return target_file
    return "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]


def _file_present(src: Path, target_file: str) -> bool | None:
    """公告指的那个文件在**这个发包里**存在吗？

    ★ 为什么要这一步：公告是挂在 PyPI **包**上的，但代码可能住同仓库的别的包
      （`langchain-core` 的公告提到 `libs/partners/openai/...`，而那是 `langchain-openai` 的文件；
       `langflow` 的代码在 `lfx`）。文件根本不在这包里 → 工具"没报"不是漏检，是**靶子错了**。
      宁可判"不适用"，也不能把它算成漏检（那会凭空压低召回）。
      返回 None = 无法判断（源码目录不在本地）。
    """
    if not src.exists():
        return None
    suf = _suffix2(target_file)
    for p in src.rglob(suf.split("/")[-1]):
        if p.as_posix().endswith(suf):
            return True
    return False


# ★ 2026-10-11：统一分母口径 —— 直接读 `tools/check_benchmark_locations.py` 出的定位结论。
#   把"修复版新增 / 跨包 / 路径写法差异 / 未备料"四种从分母里剔掉（它们是**靶子问题**，不是漏检）。
_LOC_BENCH = ROOT / "data" / "target_pool" / "version_benchmark_loc.json"
_LOC_STATUS: dict[tuple, str] = {}
if _LOC_BENCH.exists():
    try:
        for _it in json.load(open(_LOC_BENCH, encoding="utf-8")).get("items", []):
            _tf = _it.get("target_file")
            if not _tf:
                continue
            _k = (_it.get("scan_package") or _it.get("package"),
                  str(_it.get("scan_version") or _it.get("version")), _tf)
            _LOC_STATUS[_k] = _it.get("_loc_status") or ""
    except Exception:
        pass

# 这些状态意味着"公告的定位落不到被扫包里" → 不计入召回分母
_LOC_EXCLUDE = {"absent", "no_src", "cross_version_path", "cross_package"}


def _loc_status_of(sp: str, sv: str, tf: str) -> str:
    return _LOC_STATUS.get((sp, str(sv), tf), "")


def _safe(s: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in s).lower()


def main() -> int:
    rd = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not rd or not (rd / "findings.tsv").exists():
        print("用法: python app/eval_version_benchmark.py <round-dir>")
        return 1
    bm = json.load(open(BM, encoding="utf-8"))["items"]
    rows = list(csv.DictReader(open(rd / "findings.tsv", encoding="utf-8-sig"),
                               delimiter="\t"))
    by_proj: dict[str, list[dict]] = {}
    for r in rows:
        by_proj.setdefault(r.get("project", ""), []).append(r)

    scored, no_loc, not_scanned, mismatch = [], [], [], []
    for it in bm:
        sp = it.get("scan_package") or it["package"]
        sv = str(it.get("scan_version") or it["version"])
        key = f"{_safe(sp)}-{_safe(sv)}"
        rec = dict(it)
        rec["target_key"] = key
        rows_p = by_proj.get(key)
        if rows_p is None:
            not_scanned.append(rec)
            continue
        rec["n_findings"] = len(rows_p)
        tf = it.get("target_file")
        if not tf:
            rec["needs_manual"] = True
            no_loc.append(rec)
            continue
        # ★ 先确认"公告指的文件在这个发包里吗" —— 不在就是**靶子错了**，不算漏检
        st = _loc_status_of(sp, sv, tf)
        if st in _LOC_EXCLUDE:
            rec["loc_status"] = st
            rec["loc_reason"] = "定位未被验证落在被扫包内（修复版新增/跨包/未备料）"
            mismatch.append(rec)
            continue
        present = _file_present(PKG_SRC / key, tf)
        rec["file_present"] = present
        rec["loc_status"] = st or ("present" if present else "unknown")
        if present is False:
            mismatch.append(rec)
            continue
        base = tf.split("/")[-1]
        suf = _suffix2(tf)
        # ★ 命中 = findings 里的路径**以公告路径的末两段结尾**（防同名文件假命中）
        found = [r for r in rows_p if suf and r.get("file", "").replace("\\", "/").endswith(suf)]
        fn = it.get("target_function") or ""
        hard = [r for r in found if fn and (fn in r.get("chain", "") or fn in r.get("entry", ""))]
        rec["n_hit"] = len(found)
        rec["hard"] = bool(hard)
        rec["hit_rows"] = [f"{r['file']}:{r['line']}" for r in (hard or found)[:5]]
        scored.append(rec)

    hit = [r for r in scored if r["n_hit"]]
    miss = [r for r in scored if not r["n_hit"]]
    print(f"★ 扫过的靶 {len(by_proj)} 个；基准条目 {len(bm)} 条")
    print(f"  自动可评测（公告给了文件名 + 文件确实在该发包里）{len(scored)} 条 "
          f"→ 命中 {len(hit)} / 漏检 {len(miss)}")
    print(f"  ★ 靶子不适用（公告的文件不在该发包里）{len(mismatch)} 条 —— **不计入分母**")
    print(f"  需人工映射 {len(no_loc)} 条；本轮没扫 {len(not_scanned)} 条\n")
    for r in hit:
        mark = "（文件名+函数都对上）" if r["hard"] else "（只文件名对上）"
        print(f"  ✓ {r['key']:34} {r.get('scan_package') or r['package']}"
              f"=={r.get('scan_version') or r['version']}  {r['target_function'] or '-'}() "
              f"@ {r['target_file']} {mark}")
        print(f"      工具报过 {r['n_hit']} 条：{r['hit_rows']}")
    for r in miss:
        print(f"  ✗ {r['key']:34} {r.get('scan_package') or r['package']}"
              f"=={r.get('scan_version') or r['version']}  {r['target_function'] or '-'}() "
              f"@ {r['target_file']} —— 该项目报过 {r.get('n_findings')} 条，但没这条文件")
    if no_loc:
        print("\n— 公告没给文件名（需人工映射，不计入自动分母）—")
        for r in no_loc:
            print(f"  · {r['key']:34} {r['summary']}")
    if mismatch:
        print("\n— ★ 靶子不适用：公告的文件不在这个发包里（不算漏检）—")
        for r in mismatch:
            print(f"  · {r['key']:34} {r['target_file']}")
    if not_scanned:
        print("\n— 本轮没扫 —")
        for r in not_scanned:
            print(f"  · {r['key']:34} {r['package']}=={r['version']}")

    total = len(scored)
    # ★ 软/硬两个口径并列（2026-10-11 补）：
    #   软 = findings 里有某条**文件末两段**对得上（一个文件里常有很多 sink，容易撞）
    #   硬 = 那条的 chain/entry 里还带上了公告给的**函数名**（真定位到那个函数）
    #   实测差距很大（44% vs 12%）→ **只报软口径会把召回吹高**，必须两个一起看。
    hard_hit = [r for r in hit if r.get("hard")]
    print(f"\n★ 静态召回（按版本建靶）= {len(hit)}/{total}"
          + (f" = {len(hit)/total:.0%}" if total else "")
          + f"   〔只文件名〕")
    print(f"   ★ 硬召回（文件名+函数）= {len(hard_hit)}/{total}"
          + (f" = {len(hard_hit)/total:.0%}" if total else "")
          + "   〔真定位到公告那个函数〕")
    print("★ 边界：真值来自公告；命中不要求判定正确；"
          "公告未给文件名的条目单列、不计入。")
    out = rd / "version_benchmark_eval.json"
    out.write_text(json.dumps({"n_scored": total, "n_hit": len(hit),
                               "n_hard_hit": len(hard_hit),
                               "hit": hit, "miss": miss, "needs_manual": no_loc,
                               "mismatch": mismatch, "not_scanned": not_scanned},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"   → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
