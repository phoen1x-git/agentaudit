# -*- coding: utf-8 -*-
"""★ is_test_path 的标准答案集 —— 12 档，改这个模块后必须全过。

跑法：
    python tools/selftest_is_test_path.py

★★ 为什么单独立一个文件（不内联进模块）：
  我第一版把用例直接写在一行python -c 里，跑完就没了。
  后面改了逻辑想回归，**没有可对照的基准**——
  只能凭记忆重写一遍用例，那份用例就失去了意义。

★ 规则类代码的所有自测都该这样：标准答案落盘、能重复跑、
  改了规则第一件事就是跑它。
"""

CASES = [
    # (路径, 期望, 为什么)
    ("registry/tests/unit/middleware/test_rbac.py", True,
     "tests 目录 + test_ 前缀 —— 核实 sample-toolkit 时看到的那批"),
    ("auth-server/tests/test_auth.py", True, "tests 目录"),
    ("src/app/routers/users.py", False, "生产代码"),
    ("examples/demo_app.py", False,
     "★ 示例应用不算测试：它常含真的可部署代码，攻击面是真的"),
    ("examples/test_demo.py", False,
     "★ examples 目录优先于test_ 前缀 —— 反向误杀测试"),
    ("benchmark/bench_test.py", False, "★ benchmark 不算测试"),
    ("docs/examples/quickstart.py", False, "docs 下"),
    ("conftest.py", True, "pytest 固件（根目录）"),
    ("tests/conftest.py", True, "pytest 固件（tests 里）"),
    ("src/test_utils.py", False,
     "★★ 生产模块恰好叫 test_utils（被 import 的真代码）—— 深度限制就是为它加的"),
    ("src/agent/testing.py", False,
     "★ testing 只作为**目录名**才算；单个模块在生产路径下是普通业务文件"),
    ("src/latest/tools/x.py", False,
     "★ 'latest' 含 'test' 子串，但目录名不等于 test → 不算（防子串误伤）"),
    ("src/contestant/src/test/test_x86_64.py", True,
     "CTF 项目里真实的 tests/test_*.py"),
    ("tests/e2e/test_login.py", True, "e2e 目录"),
    ("src/fixtures/data.py", True, "fixtures 目录"),
    # ---- ：包名 tests目录 vs 业务模块 tests 目录，**原理上不可分** ----
    #   这两档的期望值 = 「我选择的约定」，不是「事实真相」。
    #   我试过用「tests 段的上一层是不是源码根」区分，第一档就误伤了最初要修的那批
    #   （registry/tests 的上一层是 monorepo 包名，不在源码根表里）。
    #   ★ 选「一律排除」的理由：误杀不可见，多留的测试代码在 files_top 里一眼能看出。
    ("backend/api/content_planning/tests/test_data.py", True,
     "★ 已知误杀：ALwrity 真实文件，这个 'tests' 是**业务模块名**（内容策划的测试数据），"
     "按约定仍当测试排除 → 会漏掉这一条生产代码（★ 已接受的代价）"),
    ("backend/api/content_planning/tests/before_after_test.py", True,
     "★ 同上，已知误杀"),
    ("backend/api/tests/test_users.py", True,
     "对照：父目录是 api（源码根）→ 真测试"),
    ("registry/tests/unit/middleware/test_rbac.py", True,
     "★ 反向：上层是 monorepo 包名 registry，不是源码根 —— "
     "与上面两条**结构上完全一样**，这正是不可分的证明"),
    ("", False, "空路径"),
    (None, False, "None"),
]


def main():
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from is_test_path import is_test_path

    bad = []
    for path, exp, why in CASES:
        got = is_test_path(path)
        ok = (got == exp)
        if not ok:
            bad.append((path, exp, got, why))
        print("%s %-56s exp=%-5s got=%-5s  %s"
              % ("OK  " if ok else "FAIL", repr(path)[:54], exp, got, why))
    print()
    if bad:
        print("★ %d / %d 档不通过 —— 规则坏了，别拿去过滤数据" % (len(bad), len(CASES)))
        return 1
    print("全部 %d 档通过" % len(CASES))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
