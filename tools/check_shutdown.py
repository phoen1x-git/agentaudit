# -*- coding: utf-8 -*-
"""关机影响体检：结果文件完整性 + 半写文件检测 + 代码文件可编译性"""
import os, sys, json, glob, py_compile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POOL = os.path.join(ROOT, "data", "target_pool")
TOOLS = os.path.join(ROOT, "tools")

print("=" * 68)
print("1. 结果文件 JSON 可解析性")
print("=" * 68)
bad = []
files = sorted(glob.glob(os.path.join(POOL, "*.json")))
for f in files:
    rel = os.path.basename(f)
    try:
        with open(f, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            n = len(data)
        elif isinstance(data, dict):
            n = len(data)
        else:
            n = "scalar"
        mt = time.strftime("%m-%d %H:%M", time.localtime(os.path.getmtime(f)))
        print(f"  OK   {rel:34s} {mt}  {n}")
    except Exception as e:
        bad.append((rel, repr(e)))
        print(f"  BAD  {rel:34s} {e!r}")
print(f"\n  -> 共 {len(files)} 个 JSON，损坏 {len(bad)} 个")

print()
print("=" * 68)
print("2. 半写文件检测（0 字节 / 截断 / 极小）")
print("=" * 68)
susp = []
for pat in ("*.json", "*.py", "*.md"):
    for f in glob.glob(os.path.join(POOL, pat)) + glob.glob(os.path.join(TOOLS, pat)):
        sz = os.path.getsize(f)
        if sz == 0:
            susp.append((f, "0 字节"))
        elif f.endswith(".json") and sz < 10:
            susp.append((f, f"仅 {sz} 字节"))
if susp:
    for f, why in susp:
        print(f"  可疑  {f}  {why}")
else:
    print("  无 0 字节 / 极小文件")

print()
print("=" * 68)
print("3. 工具脚本可编译性（关机是否写坏代码）")
print("=" * 68)
pys = sorted(glob.glob(os.path.join(TOOLS, "*.py")))
nbad = 0
for f in pys:
    rel = os.path.basename(f)
    try:
        py_compile.compile(f, doraise=True, cfile=os.path.join(
            ROOT, "data", "_pyc.tmp"))
        print(f"  OK   {rel}")
    except Exception as e:
        nbad += 1
        print(f"  BAD  {rel}: {e}")
print(f"\n  -> 共 {len(pys)} 个脚本，语法错 {nbad} 个")
try:
    os.remove(os.path.join(ROOT, "data", "_pyc.tmp"))
except OSError:
    pass

print()
print("=" * 68)
print("4. 关机前最后 20 分钟内被修改的文件（判断有无任务在跑）")
print("=" * 68)
root_mtime = {}
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames
                   if d not in (".venv", "__pycache__", "_src_cache", ".git")]
    for fn in filenames:
        p = os.path.join(dirpath, fn)
        try:
            root_mtime[p] = os.path.getmtime(p)
        except OSError:
            pass
newest = sorted(root_mtime.items(), key=lambda kv: -kv[1])[:20]
for p, mt in newest:
    rel = os.path.relpath(p, ROOT)
    print(f"  {time.strftime('%m-%d %H:%M:%S', time.localtime(mt))}  {rel}")

print()
print("=" * 68)
print("5. 缓存目录完整性")
print("=" * 68)
cache = os.path.join(POOL, "_src_cache")
if os.path.isdir(cache):
    allf = []
    for dp, dn, fn in os.walk(cache):
        for x in fn:
            allf.append(os.path.join(dp, x))
    zero = [f for f in allf if os.path.getsize(f) == 0]
    print(f"  缓存文件 {len(allf)} 个，0 字节 {len(zero)} 个")
    for f in zero[:10]:
        print(f"    0 字节: {f}")
else:
    print("  缓存目录不在 POOL 下，往下找：")
    for dp, dn, fn in os.walk(ROOT):
        if "_src_cache" in dn:
            print(f"    {os.path.join(dp, '_src_cache')}")
            dn.remove("_src_cache")

print()
print("=" * 68)
print(f"体检结论：JSON 损坏 {len(bad)}，可疑文件 {len(susp)}，语法错 {nbad}")
print("=" * 68)
sys.exit(1 if (bad or nbad) else 0)
