# -*- coding: utf-8 -*-
"""★★★★★ 判据自测总入口 —— 改完 ast_criteria.py 就跑这个，别挑着跑。

★ 为什么必须有这个：
  我改了 4 轮判据，每次都只记得"上次跑过哪个自测"，漏掉另一个，
  然后在第二批落盘之后才发现漏了。
  → **判据类改动的验证必须是一条命令，不是一串命令。**
  → 漏跑一个的代价：整批数据作废（每批 5-8 分钟 × 6 片）。

用法：
    python tools/run_selftests.py

退出码非 0 = 有档FAIL，**别启动批次**。
"""
import io
import os
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8",
                              errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))

# ★ 顺序按「模块依赖」排：别名收集 -> 测试文件判定 -> 请求参数 -> 豁免
SUITES = [
    ("selftest_wrapper_forward.py", "★ 第6种写法的转发链（10 档）"),
    ("selftest_auth.py", "鉴权判定（14 档）"),
    ("selftest_auth_alias.py", "★ 类型别名收集 / PEP 695（8 档）"),
    ("selftest_is_test_path.py", "★ 测试文件判定（21 档）"),
    ("selftest_req_param.py", "★ 请求对象识别（18 档）"),
    ("selftest_wellknown.py", "★ 协议性公开豁免（14 档）"),
    ("selftest_router_deps.py", "★★★★ router 级 dependencies（16 档）"),
    ("selftest_wrapper_self.py", "★★★★ 包装函数别把自己当鉴权（11 档）"),
    ("selftest_evidence_file.py", "★★★★★ evidence 的 file 得是文件路径（13 档）"),
    ("selftest_crossfile_alias.py", "★★★★★★ 跨文件类型别名（12 档）"),
]

PY = sys.executable
fails = []
print("=" * 74)
print("判据自测总入口—— 共 %d 套" % len(SUITES))
print("=" * 74)

for script, desc in SUITES:
    path = os.path.join(HERE, script)
    if not os.path.exists(path):
        print("  %-26s ★ 文件不存在" % script)
        fails.append(script)
        continue
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([PY, "-W", "ignore::SyntaxWarning", "-u", path],
                       capture_output=True, env=env, cwd=HERE)
    out = r.stdout.decode("utf-8", "replace")
    tail = [ln for ln in out.strip().split("\n") if ln.strip()][-1:]
    mark = "OK  " if r.returncode == 0 else "FAIL"
    print("  %s %-26s %s" % (mark, script, desc))
    if tail:
        print("       %s" % tail[0])
    if r.returncode != 0:
        fails.append(script)
        # 把失败档打出来，别让人再去翻文件
        for ln in out.split("\n"):
            if ln.strip().startswith("FAIL"):
                print("       %s" % ln.rstrip())

print("-" * 74)
if fails:
    print("★★ 失败 %d / %d：%s" % (len(fails), len(SUITES),
                                    ", ".join(fails)))
    print("★★ **别启动批次** —— 判据有未验证的改动。")
    sys.exit(1)
print("全部通过。★ 下一个动作：拿最小项目烟测（20 秒），再启动批次。")
