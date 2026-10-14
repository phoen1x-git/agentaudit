"""A1 · 校验「版本基准·带定位条目」的定位是否**落到被扫包内**，并可对某轮结果算纠正后召回。

    # ① 只看基准：每条带定位条目落到哪儿了
    python tools/check_benchmark_locations.py
    python tools/check_benchmark_locations.py --write      # 回写 *_loc.json（加 _loc_status/_loc_detail）
    # ② 直接对某轮结果算「纠正分母后的召回」（分母污染单列，不算漏检）
    python tools/check_benchmark_locations.py --scan out/round-pkg-v1

★ 为什么需要（docs/139 §五 缺口 B / docs/140）：
  「带定位公告」的 `target_file` 有三类**分母污染**，会让召回**虚低**：
    1. `location_is_fix` —— 定位到的是**修复版新增的文件**（如 pydantic-ai `_ssrf.py`，
       被扫版本里根本没有这个文件）；
    2. `cross_package`  —— 公告挂在 A 包，但代码在**同仓的兄弟包** B
       （如 `langchain-core` 的公告指向 `libs/partners/openai/...` = langchain-openai）；
    3. `/Users/...` 之类**带作者本机绝对路径 / 站点包绝对路径**的定位（末两段可能对得上也可能不）。
  ★ 这三类都**不该计入召回分母**——否则我们的召回率被"永远不可能命中"的条目拉低，
    这是 `docs/109`/`docs/120` 同类的"分母污染"问题。

判据（按强度）：
  - 末两段路径能对上（`.../a/b.py`）→ `present`（正常，计入分母）
  - 只有 basename 对上（多处同名）→ `present_same_name`（弱命中，仍计，但标注）
  - 源码没在本机备料 → `no_src`（无法判断，**不计入分母**）
  - 完全不存在：
      · basename 在**同包其他已备料版本**里存在 → `cross_version_path`
        （路径写法/版本差异，**不计入分母**，但要单列）
      · 从来没见过这个 basename → `absent`（★ 最可疑：很可能是"修复版新增文件"= `location_is_fix`）
  - `--scan` 时，若该文件在**被扫轮的 findings 里出现过**（不管哪条），
    则一律 `present`（说明备料树与扫描树不同源，以扫描为准）。
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parent.parent
PKG_ROOT = ROOT.parent / "_targets" / "pkg"
DEFAULT_BENCH = ROOT / "data" / "target_pool" / "version_benchmark.json"

# 不计入召回分母的（分母污染 / 无法判断）
NOT_SCORABLE = {"absent", "no_src", "cross_package", "cross_version_path"}


def _safe(s: str) -> str:
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in str(s)).lower()


def _tail2(f: str) -> str:
    parts = [p for p in str(f).replace("\\", "/").split("/") if p and p not in (".", "..")]
    return "/".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else str(f))


def _src_of(sp: str, sv: str) -> Path:
    return PKG_ROOT / f"{_safe(sp)}-{_safe(sv)}"


def classify(scan_pkg: str, scan_ver: str, target_file: str,
             siblings: dict[str, set[str]] | None = None) -> tuple[str, str]:
    """→ (status, detail)。status ∈ present / present_same_name / absent /
    no_src / cross_version_path。siblings: {basename -> {pkg-ver,...}} 供跨版本判断。"""
    src = _src_of(scan_pkg, scan_ver)
    if not src.exists():
        return "no_src", "本机未备料该版本源码"
    base = str(target_file).replace("\\", "/").split("/")[-1]
    tail = _tail2(target_file)
    exact = [p for p in src.rglob(base) if p.as_posix().endswith(tail)]
    if exact:
        return "present", exact[0].relative_to(src).as_posix()
    same = list(src.rglob(base))
    if same:
        return "present_same_name", f"{len(same)} 处同名（如 {same[0].relative_to(src).as_posix()}）"
    # 不存在：看是不是"别的版本有"（路径写法差异）还是"从没见过"（疑似修复版新增）
    if siblings and base in siblings:
        return "cross_version_path", f"该包其它版本有同名文件：{sorted(siblings[base])[:4]}"
    return "absent", "★ 该包任何已备料版本都没有这个文件名（疑似修复版新增）"


def _build_sibling_index() -> dict[str, dict[str, set[str]]]:
    """{pkg: {basename: {ver,...}}}"""
    idx: dict[str, dict[str, set[str]]] = {}
    if not PKG_ROOT.exists():
        return idx
    for d in PKG_ROOT.iterdir():
        if not d.is_dir():
            continue
        # 目录名 = <pkg安全的>-<ver安全的>，无法可靠拆分 → 用包名前缀贪婪匹配
        name = d.name
        base_set: set[str] = set()
        for p in d.rglob("*.py"):
            base_set.add(p.name)
        # 用包名（去掉最后的 -<ver>）当 key：取 "-" 分隔后去掉最后一段
        parts = name.rsplit("-", 1)
        pkg = parts[0] if len(parts) == 2 else name
        ver = parts[1] if len(parts) == 2 else "?"
        idx.setdefault(pkg, {})
        for b in base_set:
            idx[pkg].setdefault(b, set()).add(ver)
    return idx


def _findings_file_set(rd: Path) -> set[str]:
    """这一轮 findings 里出现过的所有文件 basename。"""
    fp = rd / "findings.tsv"
    if not fp.exists():
        return set()
    out: set[str] = set()
    for r in csv.DictReader(open(fp, encoding="utf-8-sig"), delimiter="\t"):
        for c in ("file", "target_file", "path"):
            v = r.get(c)
            if v:
                out.add(str(v).replace("\\", "/").split("/")[-1])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", default=str(DEFAULT_BENCH))
    ap.add_argument("--write", action="store_true", help="把 _loc_status 回写进 *_loc.json")
    ap.add_argument("--scan", default=None, help="对某轮结果算纠正分母后的召回")
    a = ap.parse_args()

    bench = Path(a.bench)
    if not bench.is_absolute():
        bench = ROOT / bench
    d = json.loads(bench.read_text(encoding="utf-8"))

    sib = _build_sibling_index()
    scanned: set[str] = set()
    if a.scan:
        scanned = _findings_file_set(Path(a.scan))

    from collections import Counter
    cnt: Counter = Counter()
    seen: dict[tuple, tuple[str, str]] = {}
    absent_rows = []
    for it in d.get("items", []):
        tf = it.get("target_file")
        if not tf:
            continue
        sp = it.get("scan_package") or it.get("package")
        sv = str(it.get("scan_version") or it.get("version"))
        key = (sp, sv, tf)
        if key in seen:
            st, det = seen[key]
        else:
            st, det = classify(sp, sv, tf, sib.get(_safe(sp).rsplit("-", 1)[0]))
            # 扫描树优先：该文件在 findings 里出现过 → 一定"在"
            if st in ("absent", "cross_version_path", "no_src"):
                b = str(tf).replace("\\", "/").split("/")[-1]
                if b in scanned:
                    st, det = "present", "findings 中出现过（扫描树可见）"
            seen[key] = (st, det)
        it["_loc_status"] = st
        it["_loc_detail"] = det
        cnt[st] += 1
        if st in ("absent", "cross_version_path"):
            absent_rows.append((it.get("key"), sp, sv, tf, det))

    n_loc = sum(cnt.values())
    print(f"带定位条目 {n_loc} 条（同一 key 重复计）")
    for k, v in cnt.most_common():
        print(f"  {v:3d}  {k}")
    scorable = n_loc - sum(cnt[k] for k in NOT_SCORABLE if k in cnt)
    print(f"→ 可计入召回分母: {scorable}"
          f"；★ 应从分母剔除: {n_loc - scorable}")
    if absent_rows:
        print("\n--- 不在被扫包内的定位（分母污染，单列不计）---")
        for kk, sp, sv, tf, det in absent_rows:
            print(f"  {kk:24} {sp}=={sv}  {tf}\n      [{det}]")

    if a.scan:
        _eval_round(Path(a.scan), d, sib, scanned)

    if a.write:
        out = bench.with_name(bench.stem + "_loc.json")
        out.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n→ 已回写 {out}")
    return 0


def _eval_round(rd: Path, bench: dict, sib, scanned: set[str]) -> None:
    """用「纠正后的分母」重算召回：分母 = 该轮扫过的、且定位确实落在包内的条目。"""
    fp = rd / "findings.tsv"
    if not fp.exists():
        print(f"\n★ --scan: {rd} 里没有 findings.tsv，跳过")
        return
    rows = list(csv.DictReader(open(fp, encoding="utf-8-sig"), delimiter="\t"))
    by_proj: dict[str, list[dict]] = {}
    for r in rows:
        by_proj.setdefault(r.get("project", ""), []).append(r)

    hit, miss, inapp, nosrc = [], [], [], []
    for it in bench.get("items", []):
        sp = it.get("scan_package") or it.get("package")
        sv = str(it.get("scan_version") or it.get("version"))
        key = f"{_safe(sp)}-{_safe(sv)}"
        if key not in by_proj:
            continue
        tf = it.get("target_file")
        if not tf:
            continue
        st, det = classify(sp, sv, tf, sib.get(_safe(sp).rsplit("-", 1)[0]))
        rec = {"key": it.get("key"), "target_key": key, "target_file": tf,
               "target_function": it.get("target_function"), "loc_status": st}
        if st in NOT_SCORABLE:
            (nosrc if st == "no_src" else inapp).append(rec)
            continue
        suf = _tail2(tf)
        found = [r for r in by_proj[key]
                 if str(r.get("file", "")).replace("\\", "/").endswith(suf)]
        fn = it.get("target_function") or ""
        hard = [r for r in found if fn and (fn in r.get("chain", "") or fn in r.get("entry", ""))]
        rec["n_hit"] = len(found)
        rec["hard"] = bool(hard)
        rec["hit_rows"] = [f"{r['file']}:{r['line']}" for r in (hard or found)[:5]]
        (hit if found else miss).append(rec)

    total = len(hit) + len(miss)
    hh = [r for r in hit if r.get("hard")]
    print(f"\n★★ 纠正分母后的召回（{rd.name}）")
    print(f"   分母 = {total} 条（扫过的靶 ∩ 定位确实在包内）")
    print(f"   软召回（末两段对得上） {len(hit)}/{total}"
          + (f" = {len(hit)/total:.0%}" if total else ""))
    print(f"   硬召回（还带上函数名）  {len(hh)}/{total}"
          + (f" = {len(hh)/total:.0%}" if total else ""))
    print(f"   单列：定位不适用 {len(inapp)} 条 / 源码未备料 {len(nosrc)} 条（均不计分母）")
    for r in hit:
        print(f"   ✓ {r['key']:24} {r['target_file']}"
              f"{' （硬）' if r.get('hard') else ''}")
    for r in miss:
        print(f"   ✗ {r['key']:24} {r['target_file']}   [{r['loc_status']}]")
    for r in inapp:
        print(f"   ○ {r['key']:24} {r['target_file']}   不计分母 [{r['loc_status']}]")


if __name__ == "__main__":
    raise SystemExit(main())
