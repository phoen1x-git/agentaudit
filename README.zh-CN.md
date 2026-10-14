# agent-scanner

[English](README.md) | **中文**

面向 **LLM / Agent 应用**的污点式漏洞扫描器：用静态分析（CodeQL）选出候选点位，
再用 LLM 辅助判定。

它最核心的设计取向是**诚实面对不确定性** —— 扫描器被刻意做成**愿意说「我不知道」**，
并且把这句话当成**一等公民**，而不是一个需要粉饰过去的结果。

> ⚠️ 当前**只支持 Python**；LLM 判定层有已知噪声 —— 见 [已知限制](#已知限制)。

---

## 为什么还要再写一个扫描器？

Agent 代码里的危险调用（`eval` / `subprocess` / `open` / `requests` …）
**不是简单的数据流问题**。一段代码里有 `eval(...)`，它到底是不是漏洞，取决于**三件事**，
而传统污点分析只答第一件：

| # | 问题 | 例子（下面两个都是**误报**） |
|---|---|---|
| ① | 有个危险调用吗？ | —— 静态分析能答 |
| ② | 它的参数**外面能控制**吗？ | 参数是**本地枚举**出来的目录名 |
| ③ | 参数**能带着 payload 走到 sink** 吗？ | 中途有 **Validator** 把它降级成了 `None` |

本项目把 ②③ 也做成了**可运行的判据**（`tools/param_taint_criteria.py`），
并把「**判定层说不知道**」当成需要如实报告的结果，而不是需要掩盖的短板。

---

## 流水线

```
选靶 → 备料（下载 + 建库）→ 静态前端（CodeQL）→ 可达性预筛 → 追入口
   → 参数贯通性判据 → LLM 判定 → 三关复核 → 实跑验证 → 出材料
```

| 阶段 | 入口 | 做什么 |
|---|---|---|
| 选靶 | `tools/target_screener.py` | 按 star / 活跃度 /「是不是 Agent」筛仓库 |
| 备料 | `tools/prepare_new_targets.py` | 下载源码 + 建 CodeQL 库；**可断点续跑** |
| 静态前端 | `core/static_frontend.py` | 跑 CodeQL 查询、解析 SARIF |
| 可达性预筛 | `tools/reachability_triage.py` | 这个点位**外面调不调得到**？ |
| 追入口 | `tools/find_entries_for_suspects.py` | 往上找调用方，看挂没挂暴露标记 |
| **参数贯通性** | `tools/param_taint_criteria.py` | 参数**可不可控** / 中途**有没有被约束**？ |
| LLM 判定 | `core/llm_judge.py` | 五个维度：`verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| 一键跑 | `app/run_all.py` | prepare → scan → report |

---

## 安装

需要 **Python 3.10+**，以及 [CodeQL CLI](https://github.com/github/codeql-cli-binaries)。

```bash
pip install -r requirements.txt

# CodeQL：解压到前端找得到的位置。
# 默认查找 <workspace>/_tools/codeql/codeql(.exe)，也可按自己的目录结构覆盖。
```

### 配置

**密钥一律从文件 / 环境变量读，绝不进版本库。**

| 环境变量 | 用途 | 默认 |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | LLM 判定的 key 文件路径 | `~/.deepseek_key` |
| `GITHUB_KEY_FILE` | GitHub token 文件路径（提高 API 额度） | `~/.github_token` |
| `AF_LLM_MAX_CNY` | **单次运行的金额硬上限**（防失控保险丝，到限硬停并报数） | `30` |
| `AF_TARGET_MAP` | `{"短名": "源码根"}` 的 JSON 映射 | 从 `core/config/targets*.yml` 读 |
| `AF_JUDGE_MT` | 判定层最大输出 token | `8000` |

---

## 快速开始

```bash
# 1) 冒烟：判据自测（离线、不花钱）
python tools/param_taint_criteria.py --selftest

# 2) 选靶（需要 GitHub token）
python tools/target_screener.py fetch
python tools/target_screener.py screen

# 3) 备料：下载 + 建库（可反复重启，已完成的会跳过）
python tools/prepare_new_targets.py --status
python tools/prepare_new_targets.py

# 4) 跑一轮
python app/run_round.py --tag my-round --targets-file core/config/targets.yml
```

★ **先看钱。** 判定层会消耗 LLM 额度；脚本会在开始时打印**预估花费**，
并且 `AF_LLM_MAX_CNY` 到限会**硬停**。

---

## 已知限制

**这些是设计上的取舍，不是 bug。**
写出来是因为 —— **如实说明不确定性，比假装精确更有用。**

- ★ **只支持 Python。** 静态前端绑在 CodeQL 的 Python 包上（`--language=python`）。
  判据逻辑本身不绑语言，但换语言意味着**重做前端**。
- ★ **LLM 判定层有噪声。** 同一条候选跑三遍，**约四分之一会改口**；
  「完美稳定」往往是**缓存假象** —— 复判时务必换 `--tag`。
- ★ **`arg_source=unknown` 的结论不可信。** 这个值意味着「模型自己也不知道参数从哪来」。
  候选筛选会把这一档**默认降级**。
- ⚠️ **「找不到调用方」≠「不可达」。** 目前只做了按名匹配，会漏掉
  跨文件 / 动态派发 / 反射。
- ⚠️ **框架中介。** 当被 `import` 的实现在 `site-packages`（不在被扫目录里）时，
  静态分析**看不到它**。
- ⚠️ **每一条发现都需要人工确认。** 工具产出的是**候选**，不是结论。

---

## 目录结构

```
core/     判据内核（静态前端 / 判定层 / 可达性 / 污点追踪 / CodeQL 查询）
tools/    可复用工具（选靶 / 备料 / 各判据 / 自检）
app/      一键入口与流程编排
```

---

## 许可证

MIT —— 见 [LICENSE](LICENSE)。

> ★ 请仅用于**你有权测试**的目标。
