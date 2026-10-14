"""把「判定层实际收到的那段输入」原样打出来，供人审阅 / 讲解用。

    python tools/show_judge_prompt.py <targets.yml> <project> [--index 0] [--pick 文件名:行]

★ 为什么要有它：讨论"判定层到底给了 LLM 什么"时，凭记忆描述不可靠。
  这个脚本**真跑一遍静态前端**，拿真实的 Finding，再调 `llm_judge._build_user`
  把即将发给模型的那段 user 内容打印出来（不发请求、不花钱）。
"""
from __future__ import annotations

import argparse
import sys
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import static_frontend as SF        # noqa: E402
from core import llm_judge as LJ              # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("targets")
    ap.add_argument("project")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--pick", default="", help="按 `文件名:行` 选（子串匹配）")
    ap.add_argument("--rubric", action="store_true", help="同时打印 system 提示词")
    a = ap.parse_args()

    cfg = yaml.safe_load((ROOT / a.targets).read_text(encoding="utf-8"))["targets"]
    t = cfg[a.project]
    db = (ROOT / t["db"]).resolve()
    fnd = SF.run_db_to_findings(str(db), a.project, on_log=lambda m: None)
    if not fnd:
        print("静态前端 0 条")
        return 2
    if a.pick:
        fnd = [f for f in fnd if a.pick in f"{f.sink_uri}:{f.sink_line}"] or fnd
    fd = fnd[min(a.index, len(fnd) - 1)]
    user, c = LJ._build_user(fd, {})
    print(f"# 该目标共 {len(fnd)} 条；下面这条是 #{a.index}："
          f"{fd.sink_func} @ {fd.sink_uri}:{fd.sink_line}")
    print("=" * 78)
    if a.rubric:
        print("【system 提示词（RUBRIC）】")
        print(LJ.RUBRIC)
        print("=" * 78)
    print("【user 内容（真正发给模型的那段）】")
    print(user)
    print("=" * 78)
    print(f"（user 长度 {len(user)} 字符；守卫行 {len(c.get('guard_lines') or [])} 行；"
          f"来源函数 {len(c.get('arg_funcs') or [])} 个）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
