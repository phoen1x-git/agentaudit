# -*- coding: utf-8 -*-
"""★ 测试文件判定 —— 要写成**独立模块**而不是内联到规则里。

为什么独立：
  规则（ast_criteria.py）一改，规则哈希就变 → 正在跑的批次全部作废。
  把「哪些路径算测试」做成可切换的独立模块后：
    -规则主体不用动（哈希不变，旧批次仍有效）
    - 想切换约定时只改这个模块 + 重跑，可对比、可回退
★ 这就是「把高频开关从主干里拆出来」—— 规则哈希成了版本锁的锚点，
  不能随便碰。

判定约定（逐条给出理由，不靠猜）：
  1. 路径里有名为 test / tests / testing / __tests__ 的**目录** → 单元测试目录
  2. 文件名形如 test_*.py 或 *_test.py                → pytest 约定
  3. conftest.py                → pytest 固件
  4. 路径里有 e2e / integration / fixtures / mocks → 测试支撑目录
  5. examples / demo / samples / example  → ★ 不算测试！
     它们是**示例应用**，常含真的可部署代码，攻击面是真的。
     （这一条特意不排除：把它算成测试 = 又一个假阴性来源。）

★★ 反向也要检查：**别把生产代码误判成测试**。
  真实踩到的坑：某个项目的生产模块叫 `test_utils.py`（真代码，被 import 的）。
  所以第 2 条要用「整路径里 tests 目录 OR 标准命名」双条件，
  并且最终仍以「这个文件会不会被 uvicorn 加载」为准。
"""
import re

# ★ 目录名（路径的任一段精确等于这些 → 测试）
#   ★ 只放**目录**约定，不放文件约定 —— `testing.py` 这种放在生产路径下的
#     单个模块是普通业务文件（实测踩过：src/agent/testing.py 是真代码）。
TEST_DIRS = {"test", "tests", "testing", "__tests__", "e2e", "integration_test",
             "integration_tests", "fixtures", "testdata", "mocks"}
# ★ 这些目录**不**算测试（防止过度排除造成假阴性）
NOT_TEST_DIRS = {"example", "examples", "demo", "demos", "sample", "samples",
                 "template", "templates", "benchmark", "benchmarks",
                 "docs", "doc", "scripts", "tools"}

# ★ 文件名约定。★ 必须要求「文件**在测试目录里**」或者「在项目根/包根」。
#   原因：`src/test_utils.py` 这种是真被import 的生产模块（踩过），
#   而 `tests/test_auth.py` 才是测试。光看test_ 前缀会把前者误杀。
_CONFTEST_RE = re.compile(r"^conftest\.py$")
_TEST_NAME_RE = re.compile(r"^(?:test_[^/]*\.py|[^/]*_test\.py)$")

# ★ 源码根：直接位于这些目录下的文件是**生产代码**，哪怕名字叫 test_*。
#   这条是第3 档的规则 —— 光看路径深度区分不了
#   （tests/test_auth.py 和 src/test_utils.py 深度一样，性质相反）。
SOURCE_ROOTS = {"src", "lib", "libs", "app", "apps", "pkg", "packages",
                "source", "sources", "python", "server", "client", "api",
                "core", "main", "internal", "cmd", "scripts_", "module"}


def is_test_path(path):
    """返回 True = 该文件按约定属于测试代码。

    ★ 约定的层次（从强到弱，先命中先返回）：
      0. 任何一段是明确的**非测试**目录（examples/benchmark/scripts…）→ 立刻 False
      1. 任何一段是 test / tests / __tests__ / e2e / fixtures… 目录→ True
      2. 文件名是 conftest.py → True
      3. 文件名是 test_*.py / *_test.py，**且**它位于「包根或更浅」
         （即路径段数 <= 3，或路径里出现过 src/ lib/ app/）→ True
         —— 这一条的深度限制就是为 `src/test_utils.py` 留的。
    """
    if not path:
        return False
    p = path.replace("\\", "/")
    parts = [x for x in p.split("/") if x and x != "."]
    if not parts:
        return False
    dirs = parts[:-1]
    low = [seg.lower() for seg in dirs]
    fn = parts[-1]

    # 0) 非测试目录优先 —— examples/ 下的 test_*.py 仍是示例应用
    for seg in low:
        if seg in NOT_TEST_DIRS:
            return False
    # 1) 测试目录
    for seg in low:
        if seg in TEST_DIRS:
            #★★★★★ 这里有一个**原理上无法从路径命名消除的歧义**（10-05 07:4x 实测撞上）：
            #
            #     registry/tests/unit/middleware/test_rbac.py   ← 真 pytest（sampleagent2-registry）
            #     backend/api/content_planning/tests/test_data.py ← ★ **业务模块**（ALwrity 真实文件）
            #
            #   `content_planning` 是「内容策划」的业务包，
            #   里面的 `tests/` 指的是「测试数据」——**整个文件是生产代码**。
            #
            #   ★ 我试过用「tests 段的上一层是不是源码根」来区分，
            #     结果**第一档就误伤了最初要修的那批**
            #     （`registry/tests/...` 的上一层是 monorepo 的包名 `registry`，
            #      不在源码根表里 → 被判成生产 → 不排除）。
            #     ★ 这两次尝试证明了：**它俩在结构上完全一样**，没有启发式能分开。
            #
            #   → 约定：**一律排除**（承认这一个可能的误杀）。
            #   ★ 选这个方向的理由只有一个：**误杀不可见**。
            #     - 漏掉一条生产代码 → 证据里少一条，**没人会发现**（假阴性）
            #     - 多留几条测试代码 → 证据里多条，`kind_hist` / `files_top` 一列就看出来，
            #       人工核实一眼能排除
            #   → 规则的失败模式必须是**可见的**。
            return True
    # 2) conftest
    if _CONFTEST_RE.match(fn):
        return True
    # 3) 文件名约定 + ★ 父目录性质
    if _TEST_NAME_RE.match(fn):
        #★ 这里不能靠「路径深度」区分（踩过）：
        #     tests/test_auth.py   深度 2 → 该算测试
        #     src/test_utils.py    深度 2 → 是真被import 的生产模块
        #   两者深度一样。真正的区分是**父目录的性质**：
        #     父目录是明确的源码根（src / lib / app / pkg / 源码包名…）→ 生产代码
        #   父目录看起来是项目根 / tests 的兄弟 → 按约定算测试。
        parent = low[-1] if low else ""
        if parent in SOURCE_ROOTS:
            return False
        return True
    return False


def split_paths(files):
    """把 {path: text} 拆成 (生产, 测试)。★ 规则入口用这个，只对生产跑。"""
    prod, test = {}, {}
    for p, t in files.items():
        (test if is_test_path(p) else prod)[p] = t
    return prod, test
