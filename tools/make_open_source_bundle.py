"""★★★ 开源前「剥离检查」：对**要传的那部分**逐行扫三类红线。

★ 背景（`docs/242`）：这个目录 **675 MB / 41284 文件**，其中 `data/target_pool/` 482 MB
  装的是「**某仓库·某文件·第几行有洞**」的点位记录。
  ⇒ **整仓库传上去 = 替上游公开还没修的洞**（同时踩两条线：用户红线「对外披露必须人工过目」+ 伤害上游）。

★ 所以：**只传内核**（`app/` + `core/` + `tools/` + 一份新 README），
  但**内核里也可能有残留**（例：`tools/verify_*.py` 是按具体候选写的实跑脚本；
  `check_disclosures.py` 里有披露渠道邮箱）⇒ ★ **必须逐行扫，不能"应该没有"。**

三类红线：
  ① **未披露漏洞细节** —— 自己关注的靶名（★ 通过 `AF_OS_TARGETS` 给，**工具不内置**）+ issue 编号/URL + verify_*.py
  ② **第三方邮箱 / 隐私**
  ③ **本机路径** —— `C:\\Users\\<你>\\...` 这类写死的绝对路径（★ 别人机器上跑不起来，且泄露本机目录）

用法：
    python tools/make_open_source_bundle.py                # 出报告
    python tools/make_open_source_bundle.py --manifest      # 同时出"要传的文件清单"
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── 要传的（★ 白名单，其余一律不传）────────────────────────────────────
KEEP_DIRS = ["app", "core", "tools"]
KEEP_TOP_FILES: list[str] = []          # README/LICENSE/requirements 由人**重写**，不直接搬

# ── ★★ 第二层：保留目录里**按文件**建议不传的（实测出来的）────────────
#    ★ 判据：① 按具体候选写的（天然带靶名+行号）② 一次性实验 ③ 含披露渠道/身份
DROP_GLOBS = {
    "tools/verify_*.py": "★★★ 按具体候选写的实跑脚本 —— 天然带「靶名 + 文件:行」",
    "tools/af2o_*": "一次性二阶（AF2O）实验：绑死某一个靶，不通用",
    # ★ 文件名用**缩写**、不含完整靶名 ⇒ 名单匹配不到，只能在这里写（glob 本身不含靶名，故安全）
    "tools/tw_verify_*": "★ 按靶命名的一次性实验（缩写）",
    "tools/repro_tw_*.py": "★ 按靶命名的一次性复现（缩写）",
    # ★★ 注意：**按靶命名的文件**不在这里硬写（否则工具源码里就留下了靶名）。
    #    它们由 `AF_OS_TARGETS` 动态生成 —— 见本文件下方 `for _t in OUR_TARGETS` 那段。
    "tools/scan_code_exec_path.py": "★ 写死三个具体靶的源码路径",
    "tools/qualify_exec_paths.py": "★ 同上，且含各行人工结论",
    "tools/type_fn_profile.py": "★ 指向 taintp2x 数据集（本机路径）",
    "tools/sink_gap_rank.py": "★ 同上",
    "tools/triage_external_gt.py": "★★ 含 SELF 账号名（你的身份）",
    "tools/pattern_sweep.py": "一次性（写死本机 python 路径）",
    "tools/resume_final_v6.py": "一次性（写死本机 python 路径）",
    "tools/check_owner_isolation.py": "一次性（写死本机日志路径）",
    # ── ★★ 针对具体候选/具体轮次写的实验与记录脚本（带「靶名 + 文件:行」）──
    "tools/after_*.py": "★ 批次收尾脚本 —— 写死「靶名 + 文件 + 行号」",
    "tools/cc_consistency.py": "★ 一致性实验 —— 写死「靶名 + 文件 + 行号」",
    "tools/criterion10_coverage.py": "★ 判据覆盖实验 —— 写死靶名与行号",
    "tools/recheck_vulns.py": "★ 复核脚本 —— 写死靶名与结论",
    "tools/sample_false_negatives.py": "★ 漏检取样 —— 写死靶与本机源码路径（其中的通用映射已抽到 `target_map.py`）",
    # ★ 注：`tools/taint_flow.py` / `fetch_src_probe.py` / `recheck.py` **要传** ——
    #   它们是**通用**组件（污点追踪 / GitHub 按需取文件 / 离线重核），且被别的工具 import。
    #   （原先按"含本机路径"误判为一次性脚本 ⇒ 已改判，见 `docs/243` 的复盘）
    "tools/crit9_taint2.py": "★ 判据实验 —— 提到某靶已确认的真漏洞",
    "tools/check_targets_health.py": "★ 写死「我们报过的靶」清单",
    "tools/select_targets_v1.py": "★ 同上",
    "tools/probe_attack_surface.py": "★ 探针 —— 写死靶的目录结构",
    "tools/probe_failopen_defaults.py": "★ 探针 —— 写死靶名与链路",
    "tools/ql_dev/*": "★ 判据开发实验目录",
    "tools/check_redundant.py": "★ 查重脚本 —— 示例里写死我们的靶",
    "tools/compare_targets.py": "★ 靶对比 —— 示例里写死我们的靶",
    "tools/root_cause_view.py": "★ 根因视图 —— 写死我们的靶与结论",
    "tools/upstream_check_candidates.py": "★ 上游查重 —— 写死我们的靶与轮次",
    "tools/find_store_points.py": "★ 二阶点扫描 —— 写死我们读过的论文靶",
    "tools/_probe_*.py": "★ 一次性探针（写死具体候选）",
    "tools/scan.py": "★ 单靶运行器 —— 示例写死我们的靶",
    "tools/run_criteria.py": "★ 判据运行 —— 举例写死我们的靶",
    "tools/eval_gt_linehit.py": "★ 语料真值评估 —— 写死外部真值靶",
    "tools/eval_gt_*.py": "★ 同上",
    "tools/gt_attribution.py": "★ 归因 —— 写死语料靶名",
    "tools/ab_rounds_points.py": "★ A/B —— 示例写死我们的靶",
    "tools/ab_*.py": "★ 一次性 A/B 实验",
    "tools/target_audit.py": "★ 靶体检 —— 写死我们核过的靶与结论",
    "tools/screen_*.py": "★ 选靶筛选的开发版（写死我们的靶）",
    "tools/_*": "★ 下划线开头的都是一次性脚本",
    # ── ★★ 基准/消融实验（绑死我们的靶，且带结论）──
    "app/exp_*.py": "★ 消融/变差实验 —— 绑死我们的靶与库",
    "app/build_advisory_benchmark.py": "★ 公告基准构建 —— 绑死我们的靶",
    "app/eval_benchmark.py": "★ 基准评估 —— 绑死我们的靶",
    "app/prepare_pkg_targets.py": "★ 打包靶准备 —— 绑死我们的靶版本",
    "app/scan_advisory_pool.py": "★ 公告池扫描 —— 含我们的靶清单",
    "app/select_batch.py": "★ 批次选择 —— 含**我们报过/已提交**的靶与单号",
    "tools/compare_all_targets.py": "★★ 靶对比 —— **直接写了「哪个靶哪儿没修」**",
    "tools/check_candidate_alive.py": "★★ 存活核查 —— 写死候选的「文件:行 + 结论」",
    "tools/repro_shlex_quote.py": "★★ 复现包 —— 针对某个靶的具体缺陷",
    "tools/find_second_order_entry.py": "★ 二阶入口 —— 写死我们的靶源码路径",
    "tools/trace_store_to_sink.py": "★ 二阶追踪 —— 写死我们的靶",
    "core/config/targets.yml": "★ 我们的靶表（repo/db/src 全在里面）",
    "core/config/upstream_repos.yml": "★ 我们的靶 → 上游仓库映射",
    "core/ql/*.bak_*": "★ 备份文件（不进版本库）",
    "tools/seed_candidate_ledger.py": "★ 候选台账种子 —— 含我们全部候选与出处",
    "tools/check_disclosures.py": "★ 披露渠道表 —— 含维护者邮箱",
    "tools/decision_table.py": "★ 候选决策记录 —— 含 issue 号与靶名",
    "tools/summarize_results.py": "汇总脚本 —— 引用我们各轮结果",
    "tools/collect_external_ground_truth.py": "★★ 含 SELF_LOGINS（你的账号名）⇒ 身份泄露",
    "tools/measure_pathfilter_blast.py": "一次性测量脚本（写死本机靶路径）",
    "tools/night_runner.py": "夜班脚本（写死本机 token 路径）",
    "tools/INDEX.md": "自动生成的索引 —— 提到靶名，**重新生成即可**",
    "tools/vendor_*": "第三方搬运",
    "core/config/targets_*.yml": "★ 我们的靶池（仓库名清单）⇒ 换成示例即可",
}

# ── 明确不传的（留档，说明理由）──────────────────────────────────────
DROP = {
    "data": "★★★ 482MB 候选点位（哪一行有洞）+ 源码/PyPI 缓存",
    "out": "每一轮的原始结果（findings）",
    "docs": "内部推理 + 未披露漏洞细节 + 上游沟通",
    "docs_night": "同上",
    "logs": "运行日志",
    "_dev": "一次性开发目录（2264 文件）",
    "_scratch": "草稿",
    "_e2e": "端到端实验",
    "_asb_*": "审计沙箱 / 专项实验目录（按具体包做的，一次性）",
    "share": "待人工确认",
}

# ── 三类红线的模式 ──────────────────────────────────────────────────
# ① 未披露漏洞细节 —— 靶名
#   ★★ 本工具**不内置任何具体靶名**（那正是要保护的信息）。
#     自己的关注名单通过下面两种方式给（都不进版本库）：
#       · 环境变量 `AF_OS_TARGETS="名字1,名字2"`（逗号分隔）
#       · 或项目根放一个 `opensource_targets.txt`（一行一个）
_T_RAW: list[str] = []
_T_RAW += [x.strip() for x in os.environ.get("AF_OS_TARGETS", "").split(",") if x.strip()]
_T_FILE = os.path.join(ROOT, "opensource_targets.txt")
if os.path.exists(_T_FILE):
    try:
        _T_RAW += [x.strip() for x in open(_T_FILE, encoding="utf-8").read().splitlines() if x.strip()]
    except Exception:
        pass
OUR_TARGETS = sorted({x for x in _T_RAW if x})
TARGET_PAT = (re.compile("|".join(re.escape(x) for x in OUR_TARGETS), re.I)
              if OUR_TARGETS else None)

# ★★ 按靶命名的文件（例：`tools/<靶>_probe.py`）⇒ 由关注名单**动态**生成排除规则，
#    这样工具源码里**不用硬写任何靶名**。
for _t in OUR_TARGETS:
    for _d in ("tools", "app", "core", "lib"):
        DROP_GLOBS[f"{_d}/*{_t}*"] = "★ 文件名含某个关注靶名 ⇒ 按靶专用，不传"
# ★ 收紧：`#\d{3,}` 会把 CSS 颜色（#666）和偏移量（#1362:8）都算进来 ⇒
#   要求 `#` 前面有**单词**（`EvoAgentX#287`）或 issue 类词（`报告 #1098`）或 `/issues/123`。
# ★ 收紧 2：`#` 前的词**不允许含点**，且**前面不能紧跟 `.` 或词字符** ——
#   否则 `app.py#1362:8`（守卫位置格式）会被当成单号。真正的单号形如 `EvoAgentX#287` / `报告 #1098`。
ISSUE_PAT = re.compile(
    r"(?<![.\w])(?:[A-Za-z][A-Za-z0-9_\-]{1,}|报告|单号|issue|Issue|PR|pr)\s*#\s*\d{2,5}\b"
    r"|/issues/\d+|private-vulnerability-reporting")
VERIFY_PAT = re.compile(r"^verify_.+\.py$|^check_disclosures\.py$|^check_candidate_alive\.py$")

# ② 邮箱（排除明显无害的）
EMAIL_PAT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
EMAIL_OK = re.compile(
    r"example\.|noreply|no-reply|localhost|@types|github\.com|users\.noreply|"
    # ★ 这些不是邮箱，是**代码里的 `x@文件名` 写法**（例：`arg0:param(socket@discovery.py:1056)`）
    r"@[A-Za-z0-9_]*(\.py|\.js|\.ts|\.json|\.yml|\.mjs|\.go)\b|"
    r"@mcp\.tool|@search\.|@router\.|@main\.|@abbr\.|@WorfBench|@app\.|@server\.|@tool\b|@register|@pytest",
    re.I)

# ③ 本机路径 —— ★★ **模式从本机推导，源码里不留任何身份**（见下）
#   ★ 原则：本工具是要**随包一起发出去的**，所以它自己的源码里
#     **不能出现真实用户名 / 真实目录名** —— 否则它自己就成了红线命中。
#   ⇒ 用户名从 `~` 推导；易泄露的目录名用环境变量补：
#      `AF_OS_LOCAL_EXTRA="某目录,某项目名"`（逗号分隔）。
_HOME = os.path.expanduser("~")
_USER = os.path.basename(_HOME.rstrip("\\/")) or ""
_EXTRA_LOCAL = [x.strip() for x in os.environ.get("AF_OS_LOCAL_EXTRA", "").split(",") if x.strip()]
_LOCAL_PARTS = [r"[A-Za-z]:[\\/]Users[\\/]", r"/home/[^/\s]+/", r"/Users/[^/\s]+/"]
if _USER:
    _LOCAL_PARTS.append(r"Desktop[\\/]" + re.escape(_USER))
_LOCAL_PARTS += [re.escape(x) for x in _EXTRA_LOCAL]
LOCAL_PAT = re.compile("|".join(_LOCAL_PARTS), re.I)

REDLINES = [
    ("①未披露漏洞细节·靶名", TARGET_PAT),
    ("①未披露漏洞细节·issue号", ISSUE_PAT),
    ("②第三方邮箱", EMAIL_PAT),
    ("③本机路径", LOCAL_PAT),
]

# ★★ **自豁免**：本工具**必须**包含这些模式串（否则没法检查别人），
#    所以扫它自己必然是误报。⇒ 明确豁免，并在报告里写明，**不假装"命中 0"**。
SELF_EXEMPT = {"tools/make_open_source_bundle.py"}


def _drop_reason(rel: str):
    """命中了 DROP_GLOBS 就返回理由，否则 None。"""
    import fnmatch
    p = rel.replace("\\", "/")
    for g, why in DROP_GLOBS.items():
        if fnmatch.fnmatch(p, g):
            return why
    return None


def _files_to_keep(root: str) -> tuple[list[str], list[tuple[str, str]]]:
    """返回 (要传, [(建议不传, 理由)])。"""
    keep, drop = [], []
    for d in KEEP_DIRS:
        base = os.path.join(root, d)
        for dp, dn, fs in os.walk(base):
            dn[:] = [x for x in dn if x not in ("__pycache__", ".pytest_cache")]
            for f in fs:
                if f.endswith(".pyc"):
                    continue
                rel = os.path.relpath(os.path.join(dp, f), root)
                why = _drop_reason(rel)
                if why:
                    drop.append((rel, why))
                else:
                    keep.append(rel)
    return sorted(keep), sorted(drop)


def scan(root: str) -> dict:
    files, dropped = _files_to_keep(root)
    hits: list[dict] = []
    per_file_redline: dict[str, set] = {}
    for rel in files:
        if rel.replace("\\", "/") in SELF_EXEMPT:      # ★ 自豁免（见上）
            continue
        p = os.path.join(root, rel)
        # ★ 文件名本身就是红线的（verify_*.py 等）
        if VERIFY_PAT.search(os.path.basename(rel)):
            hits.append({"file": rel, "line": 0, "cat": "①未披露漏洞细节·按候选写的实跑脚本",
                         "text": "（整个文件都是针对某个具体候选靶的）"})
            per_file_redline.setdefault(rel, set()).add("①")
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    for cat, pat in REDLINES:
                        if pat is None:        # 例：没给靶名名单时跳过"①·靶名"这一项
                            continue
                        m = pat.search(line)
                        if not m:
                            continue
                        if cat == "②第三方邮箱" and EMAIL_OK.search(m.group(0)):
                            continue
                        hits.append({"file": rel, "line": i, "cat": cat,
                                     "text": line.strip()[:160]})
                        per_file_redline.setdefault(rel, set()).add(cat[0])
        except Exception as e:
            hits.append({"file": rel, "line": 0, "cat": "读取失败",
                         "text": f"{type(e).__name__}"})
    return {"files": files, "dropped": dropped, "hits": hits,
            "files_with_hits": {k: sorted(v) for k, v in per_file_redline.items()}}


def export(root: str, dest: str, files: list[str], dropped: list, hits: list) -> dict:
    """★ 把"要传的"复制到**新文件夹**（原目录一个文件都不动）。

    ★ 同时写一份 `PACKAGING.md` 进包里 —— 说明「装了什么 / 没装什么 / 还剩什么没清」，
      这样这个包**自己是自解释的**（换成别人打开也知道哪些是故意不带）。
    """
    import shutil
    if os.path.exists(dest):
        n = len(os.listdir(dest))
        if n:
            raise SystemExit(f"★ 目标文件夹已存在且非空（{n} 项）：{dest}\n"
                             f"  ⇒ 为避免覆盖，请先确认或换目录（加 --export-dir）。")
    os.makedirs(dest, exist_ok=True)
    n = 0
    for rel in files:
        src = os.path.join(root, rel)
        dst = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        n += 1

    bycat: dict[str, int] = {}
    for h in hits:
        bycat[h["cat"]] = bycat.get(h["cat"], 0) + 1

    md = ["# 打包说明（自动生成 —— `tools/make_open_source_bundle.py --export`）\n",
          "> ★ 这个包是**从原始工作目录剥出来的**，原目录**一个文件都没改**。\n",
          "## 进了什么\n",
          f"- `app/` + `core/` + `tools/`，共 **{n}** 个文件（相对路径原样保留）。",
          "- ⚠️ **README / LICENSE / requirements.txt / .gitignore 还没写** —— 这四样要**新写**，",
          "  旧 README 是内部口吻，**不要直接搬**。\n",
          "## 故意没进的（整目录）\n",
          "| 目录 | 为什么 |", "|---|---|"]
    for d, why in sorted(DROP.items()):
        md.append(f"| `{d}/` | {why} |")
    md += ["\n## 故意没进的（保留目录里按文件）\n",
           "| 文件 | 为什么 |", "|---|---|"]
    for f, why in dropped[:60]:
        md.append(f"| `{f}` | {why} |")
    if len(dropped) > 60:
        md.append(f"| …另有 {len(dropped) - 60} 个 | |")
    md += ["\n## ⚠️ 包里**仍然残留**的红线（**还没清，push 前必须处理**）\n",
           "| 类别 | 处数 |", "|---|---|"]
    for c, k in sorted(bycat.items(), key=lambda kv: -kv[1]):
        md.append(f"| {c} | {k} |")
    md += ["\n★ 处理清单见原目录 `docs/243`；处理完**回原目录重跑本工具**直到残留归零。\n"]

    open(os.path.join(dest, "PACKAGING.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")
    return {"dir": dest, "n_copied": n, "n_dropped": len(dropped), "residual": sum(bycat.values())}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", action="store_true", help="同时输出要传的文件清单")
    ap.add_argument("--export", action="store_true",
                    help="★ 把要传的复制到新文件夹（原目录不动）")
    ap.add_argument("--export-dir",
                    default=os.path.join(os.path.expanduser("~"), "Desktop", "agent-scanner"),
                    help="导出目标（默认桌面上的 agent-scanner，★ 原项目之外）")
    ap.add_argument("--root", default="", help="★ 要扫哪个目录（默认=本工具的上级目录）")
    ap.add_argument("--report-dir", default="", help="报告写哪（默认 <root>/data/target_pool）")
    a = ap.parse_args()

    root = a.root or ROOT
    rep_dir = a.report_dir or os.path.join(root, "data", "target_pool")
    os.makedirs(rep_dir, exist_ok=True)

    root = ROOT
    res = scan(root)
    files, hits, dropped = res["files"], res["hits"], res["dropped"]

    L = ["# 开源「剥离检查」报告\n",
         "> ★ 只扫**要传的那部分**（`app/` + `core/` + `tools/`），逐行查三类红线。",
         "> ★ 工具：`tools/make_open_source_bundle.py`（0 元、纯本地）。\n",
         "## 一、传与不传\n",
         f"- ★ **要传**（清洗后）：**{len(files)}** 个文件",
         f"- ❌ **保留目录里按文件不传**：**{len(dropped)}** 个",
         "- 另需**新写**：`README.md` / `LICENSE` / `requirements.txt` / `.gitignore`（**不直接搬旧的**）\n",
         "### 1.1 整个目录不传（逐条给理由）\n",
         "| 目录 | 为什么不传 |", "|---|---|"]
    for d, why in sorted(DROP.items()):
        L.append(f"| `{d}/` | {why} |")

    L += ["\n### 1.2 ★ 保留目录里、**按文件不传**的（实测出来的）\n",
          "| 文件模式 | 数量 | 为什么 |", "|---|---|---|"]
    import collections as _c
    byg = _c.Counter(why for _f, why in dropped)
    for g, why in DROP_GLOBS.items():
        if byg.get(why):
            L.append(f"| `{g}` | {byg[why]} | {why} |")

    L += ["\n## 二、★ 红线命中（**清洗后仍残留的**，要人工处理）\n",
          "> ★ **已自豁免**：" + "、".join(f"`{x}`" for x in sorted(SELF_EXEMPT))
          + " —— 本工具**必须**包含这些模式串，扫它自己必然是误报。\n"]
    if not hits:
        L.append("★ 没扫到任何命中。")
    else:
        bycat: dict[str, list] = {}
        for h in hits:
            bycat.setdefault(h["cat"], []).append(h)
        L.append(f"共 **{len(hits)}** 处命中，涉及 **{len(res['files_with_hits'])}** 个文件。\n")
        for cat, lst in sorted(bycat.items()):
            L.append(f"### {cat} —— {len(lst)} 处\n")
            for h in lst[:25]:
                L.append(f"- `{h['file']}`" + (f":{h['line']}" if h["line"] else "")
                         + f"  · {h['text']}")
            if len(lst) > 25:
                L.append(f"- …另有 {len(lst) - 25} 处")

    L += ["\n## 三、处理建议\n",
          "1. ★★ **按候选写的实跑脚本**（`tools/verify_*.py`）**整文件不传** —— "
          "它们天然带靶名 + 行号；要传就改成**通用骨架**（`tools/make_verify.py` 就是通用版）；",
          "2. ★★ **带披露渠道的**（如 `check_disclosures.py`）**不传**或**删掉邮箱表**；",
          "3. ★ **靶名出现**的地方：多数是「默认靶列表/示例」 ⇒ 换成占位符（`owner/repo`）；",
          "4. ★ **本机路径**：把默认值改成 `None`（顺带修 `docs/242` 的 A1）；",
          "5. ★ 处理完**重跑本工具**，直到「命中 0」或「命中都已被人工确认无害」。\n",
          "★ **纪律**：本工具**只报告、不改文件**；改不改、怎么改，**由人定**。"]

    report = "\n".join(L) + "\n"
    out = os.path.join(ROOT, "data", "target_pool", "opensource_bundle_report.md")
    open(out, "w", encoding="utf-8").write(report)
    print(report)
    print("报告:", out)

    if a.manifest:
        mf = os.path.join(ROOT, "data", "target_pool", "opensource_bundle_manifest.json")
        json.dump({"_meta": {"kept_dirs": KEEP_DIRS, "n_files": len(files),
                             "n_dropped_in_kept_dirs": len(dropped),
                             "redline_hits": len(hits)},
                   "keep_files": files,
                   "drop_dirs": DROP,
                   "drop_files_in_kept_dirs": [{"file": f, "why": w} for f, w in dropped],
                   "files_with_hits": res["files_with_hits"]},
                  open(mf, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print("清单:", mf)

    if a.export:
        info = export(root, a.export_dir, files, dropped, hits)
        print("\n" + "=" * 70)
        print(f"★★ 已打包到新文件夹（★ 原目录一个文件都没动）：")
        print(f"     {info['dir']}")
        print(f"   · 复制 {info['n_copied']} 个文件 ｜ 故意没进 {info['n_dropped']} 个")
        print(f"   · ⚠️ 包里仍残留红线 {info['residual']} 处（**push 前必须清**）")
        print(f"   · 包内附 `PACKAGING.md`（说明装了什么/没装什么/还剩什么）")
        print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
