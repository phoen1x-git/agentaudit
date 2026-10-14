# agent-scanner

**A taint-style vulnerability scanner for LLM / Agent applications.**
Static analysis (CodeQL) + LLM-assisted triage, with an explicit emphasis on **honest
uncertainty** — the checker is designed to say *"I don't know"* instead of guessing.

> 面向 **LLM / Agent 应用**的污点式漏洞扫描器：静态分析（CodeQL）选出候选点位，
> 再用 LLM 辅助判定。**它明确区分「确认」和「不知道」**，绝不把猜测写成结论。
>
> ⚠️ 当前**只支持 Python**；LLM 判定有已知噪声，见下方 [Known limitations](#known-limitations)。

---

## Why another scanner?

Agent 应用的危险调用（`eval` / `subprocess` / `open` / `requests` …）**不是简单的数据流问题**：

一段代码里有 `eval(...)`，它到底是不是漏洞，取决于**三件事**，而传统污点分析只答第一件：

| # | 问题 | 例子（都是**误报**） |
|---|---|---|
| ① | 有个危险调用吗？ | —— 静态分析能答 |
| ② | 它的参数**外面能控制**吗？ | 参数是**本地枚举**出来的目录名 |
| ③ | 参数**能带着 payload 走到 sink** 吗？ | 中途有 **Validator** 把它降级成了 `None` |

本项目把 ②③ 也做成了**可运行的判据**（`tools/param_taint_criteria.py`），
并把「判定层说不知道」当成**一等公民**去处理，而不是硬凑一个结论。

---

## Pipeline

```
选靶 → 备料(下载+建库) → 静态前端(CodeQL) → 可达性预筛 → 追入口 → 参数贯通性
   → LLM 判定 → 三关复核 → 实跑验证 → 出材料
```

| 阶段 | 入口 | 说明 |
|---|---|---|
| 选靶 | `tools/target_screener.py` | 按 star / 活跃度 / 「是不是 Agent」筛仓库 |
| 备料 | `tools/prepare_new_targets.py` | 下载源码 + 建 CodeQL 库；**可断点续跑** |
| 静态前端 | `core/static_frontend.py` | CodeQL 查询 + SARIF 解析 |
| 可达性预筛 | `tools/reachability_triage.py` | 判「外面调不调得到」 |
| 追入口 | `tools/find_entries_for_suspects.py` | 往上找调用方，看挂没挂暴露标记 |
| **参数贯通性** | `tools/param_taint_criteria.py` | 判「参数可不可控 / 中途有没有校验」 |
| LLM 判定 | `core/llm_judge.py` | 五个维度：`verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| 一键跑 | `app/run_all.py` | prepare → scan → report |

---

## Install

需要 **Python 3.10+**，以及 [CodeQL CLI](https://github.com/github/codeql-cli-binaries)。

```bash
pip install -r requirements.txt

# CodeQL：下载后解压，让 core/static_frontend.py 能找到它
#   默认找 <workspace>/_tools/codeql/codeql(.exe)，也可用环境变量指定
```

### 配置（**密钥一律走环境变量 / 文件，不进版本库**）

| 环境变量 | 用途 | 默认 |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | LLM 判定的 key 文件路径 | `~/.deepseek_key` |
| `GITHUB_KEY_FILE` | GitHub token 文件路径（提高 API 额度） | `~/.github_token` |
| `AF_LLM_MAX_CNY` | **单次运行的金额硬上限**（防失控保险丝，到限硬停报数） | `30` |
| `AF_TARGET_MAP` | `{"短名": "源码根"}` 的 JSON 映射 | 从 `core/config/targets*.yml` 读 |
| `AF_JUDGE_MT` | 判定层最大输出 token | `8000` |

---

## Quick start

```bash
# 1) 冒烟：判据自测（不联网、不花钱）
python tools/param_taint_criteria.py --selftest

# 2) 选靶（需要 GitHub token）
python tools/target_screener.py fetch
python tools/target_screener.py screen

# 3) 备料：下载 + 建库（可反复重启，已完成的会跳过）
python tools/prepare_new_targets.py --status
python tools/prepare_new_targets.py

# 4) 单轮扫描
python app/run_round.py --tag my-round --targets-file core/config/targets.yml
```

★ **跑之前先看钱**：判定层会消耗 LLM 额度。
脚本会在开始时打印**预估花费**，并且 `AF_LLM_MAX_CNY` 到限会**硬停**。

---

## Known limitations

**这些是设计上的取舍，不是 bug —— 写出来是因为「诚实标注不确定性」比「假装准确」有用。**

- ★ **只支持 Python**：静态前端绑在 CodeQL 的 Python 包上（`--language=python`）。
  判据逻辑本身不绑语言，但换语言要重做前端。
- ★ **LLM 判定有噪声**：同一条候选跑三遍，**约四分之一会改口**；
  「完美稳定」往往是**缓存假象**（复判必须换 `--tag`）。
- ★ **`arg_source=unknown` 的 `vuln` 不可信** —— 那意味着「模型自己也不知道参数从哪来」。
  本项目的候选筛选会把这一档**默认降级**。
- ⚠️ **「找不到调用方」≠「不可达」**：只做了按名匹配，跨文件 / 动态调用 / 反射会漏。
- ⚠️ **框架中介**：`import` 指向的实现在 `site-packages`（不在靶目录）⇒ 静态看不到它。
- ⚠️ **报告里的每条候选都需要人工确认**。工具产出的是**候选**，不是结论。

---

## Repo layout

```
core/     判据内核（静态前端 / 判定层 / 可达性 / 污点追踪 / CodeQL 查询）
tools/    可复用工具（选靶 / 备料 / 各判据 / 校验器）
app/      一键入口与流程编排
```

---

## License

MIT —— 见 [LICENSE](LICENSE)。

> ★ 请仅用于**你有权测试**的目标。
