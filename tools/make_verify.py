"""H · 实跑复现半自动化：按 sink 家族生成 `verify_*.py` 骨架。

★★ 先说清楚它**不是**什么：
   它生成的是**骨架**，不是**证据**。骨架里有两处**必须由人补**（都带 `TODO(人)` 标记）：
     ① **逐字复刻**目标代码的那一段（模板只给占位，不给"看起来像"的近似实现）；
     ② **断言**（读到哨兵才算成功）。
   ★ 在补完之前，脚本里的 `REPRODUCED` 恒为 `False`，跑出来只会打印「未完成」。
   ⇒ 这样设计是为了**防止**"骨架一跑就说 verified" —— 那是本项目最重的约束之一。

★ 骨架自带的四条纪律：
   · 沙箱目录用**纯 ASCII 路径**（中文路径会干扰 URL / 编码，踩过）
   · **在进程内**触发，不开端口、不外联
   · 用**哨兵串**判成败，不用"看起来成功了"
   · 结束时打印**边界清单**（post-auth？patch 了什么？是否端到端？）

用法：
    python tools/make_verify.py --fp "sample-toolkit:file_toolkit.py:123" --sink "Attribute.join"
    python tools/make_verify.py --fp "x:y.py:1" --sink "requests.get" --family ssrf --name mylab
"""
from __future__ import annotations

import argparse
import os
import re
import secrets

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ★ sink 家族表（与 tools/root_cause_view.py 的 FAMILIES 保持同一套语义）
FAMILY_OF = [
    ("path_traversal", ("join", "__truediv__", "abspath", "normpath", "realpath")),
    ("code_exec", ("eval", "exec", "compile", "__import__", "subprocess", "popen", "system")),
    ("ssrf", ("requests", "httpx", "urllib", "aiohttp", "urlopen", "base_url")),
    ("arbitrary_read", ("open", "read_text", "read_bytes")),
    ("delete_move", ("remove", "rmtree", "unlink", "rename", "shutil")),
]


def family_of(sink: str) -> str:
    s = (sink or "").lower()
    for fam, keys in FAMILY_OF:
        for k in keys:
            if k in s:
                return fam
    return "generic"


def slugify(fp: str) -> str:
    s = re.sub(r"[^A-Za-z]+", "_", fp).strip("_").lower
    return s[-48:] or "lab"


COMMON_HEAD = '''"""{doc}

★ 由 tools/make_verify.py 生成（H 项）。**这是骨架，不是证据** —— 见文件里两处 TODO(人)。

    python {script}
"""
from __future__ import annotations

import os
import shutil

# ★ 纯 ASCII 沙箱路径（中文路径会干扰 URL / 编码 —— 踩过）
#   ⇒ 放在**用户主目录**下（不写死任何人的绝对路径）
BASE = os.path.join(os.path.expanduser("~"), "_verify_{slug}")
SENTINEL = "SENTINEL-{token}"          # ★ 哨兵串：读到它才算成功
REPRODUCED = False                      # ★ 补完两处 TODO 之前，恒为 False


def _setup():
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)


def _teardown():
    shutil.rmtree(BASE, ignore_errors=True)


def _boundaries() -> str:
    """★ 报告里必须原样带上的边界。"""
    return (
        "  边界（必写进报告）：\\n"
        "   1. [ ] 是否需要登录（post-auth？复现时绕过了鉴权吗）\\n"
        "   2. [ ] 复现时 patch / 替换了什么（列出，并说明是否影响结论）\\n"
        "   3. [ ] 是否做过端到端部署验证（没有就写「未做」）\\n"
        "   4. [ ] 这是**静态核对**还是**实跑**（实跑才配 REPRODUCED=True）"
    )
'''

TEMPLATES = {}

TEMPLATES["path_traversal"] = '''
def repro(attacker_input: str) -> str:
    """★ TODO(人)：把目标代码里**属于本漏洞的那几行**逐字抄进来。

    规则（必须能回答）：攻击者输入怎么走到路径拼接？中间有没有校验/规范化？
    下面只是**占位**，不是目标的实现 —— 抄之前不许跑。
    """
    static_dir = os.path.join(BASE, "static")
    os.makedirs(static_dir, exist_ok=True)
    open(os.path.join(static_dir, "index.html"), "w", encoding="utf-8").write("<html>INDEX</html>")
    # 目标代码长这样（示例）：
    #     file_path = os.path.join(static_dir, path)
    #     if os.path.isfile(file_path): return FileResponse(file_path)
    raise NotImplementedError("TODO(人)：逐字复刻目标代码")


def main():
    _setup()
    try:
        # 哨兵文件放在 static/ **外面** —— 读得到它才算穿越成功
        secret = os.path.join(BASE, "secret.txt")
        open(secret, "w", encoding="utf-8").write(SENTINEL)
        payload = "../secret.txt"
        print(f"[payload] {payload!r}")
        got = repro(payload)
        ok = SENTINEL in str(got)
        print(f"[result ] {str(got)[:120]!r}")
        print(f"[verdict] {'实跑通过' if ok and REPRODUCED else '未完成（TODO 没补 / 未复现）'}")
        print(_boundaries())
    finally:
        _teardown()
'''

TEMPLATES["ssrf"] = '''
def repro(attacker_input: str) -> str:
    """★ TODO(人)：逐字复刻目标代码里发请求的那几行。

    方法：**起一个假的本地端点收请求**，不连真 LLM、不外联。
    规则：请求真的发出去了吗？目标地址是攻击者可控的，还是写死的常量？
    """
    # 目标代码长这样（示例）：
    #     ChatOpenAI(base_url=body.base_url).invoke(...)
    raise NotImplementedError("TODO(人)：逐字复刻目标代码")


def main():
    _setup()
    try:
        # ★ 假端点：用 http.server 监听 127.0.0.1 的一个高位端口，只记录收到了请求
        #   （不外联、不访问真服务）
        payload = "http://127.0.0.1:8765/v1"
        print(f"[payload] {payload!r}")
        got = repro(payload)
        ok = "RECEIVED" in str(got)
        print(f"[result ] {str(got)[:120]!r}")
        print(f"[verdict] {'实跑通过' if ok and REPRODUCED else '未完成（TODO 没补 / 未复现）'}")
        print(_boundaries())
    finally:
        _teardown()
'''

TEMPLATES["arbitrary_read"] = '''
def repro(attacker_input: str) -> str:
    """★ TODO(人)：逐字复刻目标代码里读文件的那几行。

    规则：路径从哪来？能不能指到沙箱外？有没有扩展名/前缀校验？
    """
    # 目标代码长这样（示例）：
    #     with open(os.path.join(data_dir, name)) as f: return f.read()
    raise NotImplementedError("TODO(人)：逐字复刻目标代码")


def main():
    _setup()
    try:
        secret = os.path.join(BASE, "secret.txt")
        open(secret, "w", encoding="utf-8").write(SENTINEL)
        payload = "../secret.txt"
        print(f"[payload] {payload!r}")
        got = repro(payload)
        ok = SENTINEL in str(got)
        print(f"[result ] {str(ok)}")
        print(f"[verdict] {'实跑通过' if ok and REPRODUCED else '未完成（TODO 没补 / 未复现）'}")
        print(_boundaries())
    finally:
        _teardown()
'''

TEMPLATES["code_exec"] = '''
def repro(attacker_input: str) -> str:
    """★ TODO(人)：逐字复刻目标代码里执行代码/命令的那几行。

    规则：执行的是什么？有没有沙箱（白名单 / __builtins__=None / shell=False）？
    用**无害的标记命令**验证执行面，绝不做破坏性动作。
    """
    # 目标代码长这样（示例）：
    #     eval(raw_value)   /   subprocess.Popen(cmd, shell=True)
    raise NotImplementedError("TODO(人)：逐字复刻目标代码")


def main():
    _setup()
    try:
        payload = "print(%r)" % SENTINEL       # ★ 无害：只打印哨兵
        print(f"[payload] {payload!r}")
        got = repro(payload)
        ok = SENTINEL in str(got)
        print(f"[result ] {str(got)[:120]!r}")
        print(f"[verdict] {'实跑通过' if ok and REPRODUCED else '未完成（TODO 没补 / 未复现）'}")
        print(_boundaries())
    finally:
        _teardown()
'''

TEMPLATES["delete_move"] = '''
def repro(attacker_input: str) -> str:
    """★ TODO(人)：逐字复刻目标代码里删除/移动的那几行。

    ★ 只在沙箱内演示。规则：目标路径能否被指到沙箱外？有没有前缀校验？
    """
    raise NotImplementedError("TODO(人)：逐字复刻目标代码")


def main():
    _setup()
    try:
        victim = os.path.join(BASE, "victim.txt")
        open(victim, "w", encoding="utf-8").write(SENTINEL)
        payload = "../victim.txt"
        print(f"[payload] {payload!r}")
        repro(payload)
        ok = not os.path.exists(victim)
        print(f"[result ] victim 还在吗: {os.path.exists(victim)}")
        print(f"[verdict] {'实跑通过（沙箱内演示）' if ok and REPRODUCED else '未完成（TODO 没补 / 未复现）'}")
        print(_boundaries())
    finally:
        _teardown()
'''

TEMPLATES["generic"] = '''
def repro(attacker_input: str) -> str:
    """★ TODO(人)：这个 sink 家族没有现成模板 —— 逐字复刻目标代码。"""
    raise NotImplementedError("TODO(人)：逐字复刻目标代码")


def main():
    _setup()
    try:
        print(f"[payload] {attacker_input!r}")
        got = repro("payload")
        print(f"[result ] {str(got)[:120]!r}")
        print("[verdict] 未完成（generic 模板，必须先补 TODO）")
        print(_boundaries())
    finally:
        _teardown()
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fp", required=True, help="project:file:line")
    ap.add_argument("--sink", required=True, help="sink 名，如 Attribute.join")
    ap.add_argument("--family", default=None, help="覆盖自动判定的家族")
    ap.add_argument("--name", default=None, help="输出文件名（默认由 fp 生成）")
    a = ap.parse_args()

    fam = a.family or family_of(a.sink)
    slug = a.name or slugify(a.fp)
    token = secrets.token_hex(4)
    doc = ("★ 实跑复现骨架 —— 目标：%s 的 %s\n"
           "（由 tools/make_verify.py 生成；★ 未补 TODO 之前不许当成证据）" % (a.fp, a.sink))

    body = COMMON_HEAD.format(doc=doc, script="tools/verify_%s.py" % slug,
                              slug=slug, token=token)
    body += TEMPLATES.get(fam, TEMPLATES["generic"])
    body += '\n\nif __name__ == "__main__":\n    main()\n'

    outp = os.path.join(ROOT, "tools", "verify_%s.py" % slug)
    open(outp, "w", encoding="utf-8").write(body)
    print("family =", fam)
    print("写出   =", outp)
    print("★ 提醒：这是骨架。必须补两处 TODO(人) 才可能 REPRODUCED=True。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
