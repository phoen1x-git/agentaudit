# agentaudit

[English](README.md) | **中文**

**给 AI Agent 做代码审计。** 静态分析 + LLM 复核的扫描器：在 LLM / Agent 代码里找出危险调用点，
并且在**拿不准的时候直接说「我不知道」**。

输出的是**候选清单**，不是「已确认的漏洞清单」。

---

## 它解决什么问题

`eval`、`subprocess`、`open`、`requests` 这类危险调用在 Agent 代码里到处都是，
传统污点分析会把它们**全都**标出来。换个问法，画面就完全不一样了：

```python
# 是候选。危险调用？是。是漏洞吗？多半不是。
handler = eval(spec_name)          # spec_name 来自本文件里的一张内置表
```

一个被标出来的点到底是不是真的，取决于三个问题，而污点分析只回答第一个：

| # | 问题 | 谁来回答 |
|---|---|---|
| ① | 有没有危险调用？ | 静态分析 |
| ② | 它的实参是不是**外部可控**？ | 本项目 |
| ③ | 这个实参能不能**活着走到 sink**？ | 本项目 |

本项目把 ② 和 ③ 做成了**可运行的检查规则**（`tools/param_taint_criteria.py`），
并且把「复核层看不出来」当成一种**要报出来的结果**（`needs_human`），
而不是硬猜一个看起来很确定的结论。

---

## 安装

需要 **Python 3.10+** 和 [CodeQL CLI](https://github.com/github/codeql-cli-binaries)（几百 MB）。

```bash
pip install -r requirements.txt

# CodeQL：默认放在项目下的 ./_tools/codeql/，或用 AF_CODEQL 指定路径。
```

### 冒烟测试（离线、不用 API key、不用 CodeQL）

```bash
python tools/run_selftests.py        # 全部自测（10 套，纯内存用例，几秒钟）
```

这是确认环境是否就绪最快的办法。

---

## 它检查哪些东西

危险函数清单在 **`core/config/sinks.yml`** —— 一个 YAML 文件，不是写死在代码里。
`core/gen_ql.py` 读它并**生成 CodeQL 查询**，所以加自己的危险函数是**改配置**，不是改代码。

| 组 | 例子 | 默认 |
|---|---|---|
| 基线 | `subprocess.run` / `Popen`、`os.system`、`requests.get/post/request`、`eval`、`exec`、`jinja2.from_string`、`*.execute(...)` | **开** |
| 数据库客户端 | 接收者名字以 `conn` 结尾的 `.query(...)` | **开** |
| 文件 I/O（`AF_SINKS_FS`） | `os.remove/unlink/rename/mkdir/chmod/...`、`shutil.move/rmtree/...` | 关 |
| 路径构造（`AF_SINKS_PATH`） | `os.path.join`、`os.path.abspath` | 关 |
| HTTP 客户端（`AF_SINKS_HTTP`） | `httpx.get/post/...`、`httpx.Request`、`httpx.Client` | 关 |
| 动态分派（`AF_SINKS_DYNIMP`） | `importlib.import_module`、`__import__`、`import_module` | 关 |

默认关的组之所以关，是因为它们吵；打开等于**用噪声换候选**。
每轮的开关取值都会记进 `meta.json`，所以只有设置相同的两轮才可以直接比。

除了 sink，内核还会查：同一文件里各端点的鉴权是否一致、同一函数里强弱写法是否并存、
以及候选能不能从入口被调到。

---

## 流水线

```
选择目标 → 下载源码 + 建库 → 静态前端（CodeQL）
  → 可达性预筛 → 追入口 → 参数贯通性检查
  → LLM 复核 → 出报告材料
```

| 阶段 | 入口 | 做什么 |
|---|---|---|
| 选择目标 | `tools/target_screener.py` | 按 star / 活跃度 /「是不是 Agent」筛仓库 |
| 下载 + 建库 | `tools/prepare_new_targets.py` | 下源码 + 建 CodeQL 库；**可断点续跑** |
| 静态前端 | `core/static_frontend.py` | 跑 CodeQL 查询，解析 SARIF |
| 可达性 | `tools/reachability_triage.py` | 这个 sink 从外面**根本调得到吗**？ |
| 追入口 | `tools/find_entries_for_suspects.py` | 往上找调用方，看有没有暴露标记 |
| **参数贯通** | `tools/param_taint_criteria.py` | 实参可控吗？沿途被约束了吗？ |
| LLM 复核 | `core/llm_judge.py` | 五个维度：`verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| 一键跑 | `app/run_all.py` | 下载 → 扫描 → 出报告 |

---

## 快速开始

一条命令就能扫——不用先准备目标清单，也不用自己建库：

```bash
python app/scan.py --demo                  # 仓库里自带的示例项目
python app/scan.py --path ./myproject      # 扫本地已有的一个项目
python app/scan.py --repo owner/name       # 拉一个 GitHub 仓库来扫
```

产物在 `out/round-<tag>/`：

| 文件 | 是什么 |
|---|---|
| `report_draft.md` | 报告草稿，一条候选一节 |
| `index.html` | 可排序 / 可搜索的候选表 |
| `findings.tsv` | 原始候选表 |
| `results.sarif` | 标准 SARIF，可进 GitHub Code Scanning 或编辑器（仅 full 模式） |

### 两种模式

| 模式 | 需要什么 | 能找出什么 |
|---|---|---|
| **full** | CodeQL CLI | CodeQL 查询 **+** AST 检查；会写 SARIF |
| **offline** | 什么都不用 | 只有 AST 检查 |

没装 CodeQL 时，它会**明说**并退回 offline 模式。每轮用的是哪种模式会记进 `meta.json`、
并印在报告开头 —— 因为两者能找出的东西不一样。`--no-codeql` 可以强制走 offline。

### Docker

不想自己装 CodeQL，就用镜像（已经打进去了）：

```bash
docker build -t agentaudit .
docker run --rm agentaudit                                             # 扫自带示例
docker run --rm -v "$PWD/myproject:/scan/myproj:ro" \
    agentaudit --path /scan/myproj --tag myproj --out /scan/out
```

### LLM 复核默认**关**

它要花 API 的钱，所以只在你明确要求时才跑：

```bash
python app/scan.py --path ./myproject --llm
```

开跑之前会先印出候选条数和硬上限（`AF_LLM_MAX_CNY`，默认 30 元），跑完报实际花费。
不加 `--llm` 就只有候选清单、没有判定 —— 报告会**如实这么说**，不会暗示已经判过。

### 手动跑流水线

`app/scan.py` 用的就是同一套引擎，也可以逐段驱动（扫一整批目标时用这个）：

```bash
# 1) 离线自测（免费）
python tools/run_selftests.py

# 2) 选目标（需要 GitHub token）
python tools/target_screener.py fetch
python tools/target_screener.py screen

# 3) 下源码 + 建库（可反复重启，已完成的会跳过）
python tools/prepare_new_targets.py --status
python tools/prepare_new_targets.py

# 4) 跑一轮
python app/run_round.py --tag my-round --targets-file core/config/targets.yml

# 5) 出报告草稿 / HTML 清单页
python app/make_report.py out/round-my-round --lang zh
python app/make_index.py  out/round-my-round --lang zh
```

> **注意花费。** 复核层要花 LLM 的钱。脚本会先打印预估花费，
> `AF_LLM_MAX_CNY` 到上限会**硬停**并报数。

---

## 输出长什么样

三个产物，成本递增：

| 产物 | 由谁产出 | 是什么 |
|---|---|---|
| `param_taint_probe.md` | `tools/param_taint_criteria.py` | 每条候选的**可控性**判定 —— **免费**，在任何 LLM 调用之前跑 |
| `findings.tsv` | `app/run_round.py` | 原始候选表，一行一条 |
| `report_draft.md` | `app/make_report.py` | 给人看的草稿，只含判成 `vuln` 的行 |

完整样例见 **[`examples/`](examples/)**（**合成示例，不引用任何真实仓库**）。
样例覆盖了扫描器区分出的四种结果：`vuln`、`not_vuln`（非外部可控）、
`not_vuln`（被校验拦住）、以及 **`needs_human`**（来源无法判定）。
最后一种才是重点：只会输出 `vuln` / `not_vuln` 的扫描器，是在**谎报自己的确定性**。

---

## 已知限制

这些是**有意的取舍**，不是 bug。

- **只支持 Python。** 静态前端绑在 CodeQL 的 Python 包上。检查逻辑本身不绑语言，
  但换语言意味着**重做前端**。
- **LLM 复核层是吵的。** 同一条候选跑三遍，大约**四分之一**的结论会变。
  「完全稳定」通常是**缓存造成的假象** —— 重判时务必换 `--tag`。
- **`arg_source=unknown` 的结论不可信。** 它表示模型自己也不知道实参从哪来；
  这类行默认被降级。
- **「没找到调用方」≠「不可达」。** 只做了按名字匹配，跨文件、动态分派、反射都会漏。
- **框架中介。** 当被 import 的实现在 `site-packages` 里（不在被扫的树里）时，静态分析看不见。
- **重新生成 CodeQL 查询需要 AgentFuzz 的参考包。** 只有「重新生成」才需要它；
  仓库里已提交的 `core/ql/*.ql` 不需要（用 `AF_PAPER_QL` 指定路径）。
- **每一条发现都需要人工确认。** 工具产出的是**候选**，不是结论。
- **offline 模式能找出的东西更少。** 没有 CodeQL 就没有跨过程可达性、也没有框架建模，
  候选清单会更短。每轮都会记下自己用的是哪种模式。

---

## 配置项

密钥一律从文件或环境变量读取，绝不进版本库。

| 环境变量 | 用途 | 默认 |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | LLM API key 文件路径 | `~/.deepseek_key` |
| `GITHUB_KEY_FILE` | GitHub token 文件路径（提高 API 限额） | `~/.github_token` |
| `AF_LLM_MAX_CNY` | **单次运行的硬上限**（到限即停并报数） | `30` |
| `AF_JUDGE_MT` | 复核层最大输出 token | `8000` |
| `AF_CODEQL` | CodeQL CLI 路径 | `./_tools/codeql/codeql[.exe]` |
| `AF_PAPER_QL` | AgentFuzz 参考 QL 包路径 | `./agentfuzz-official/ql` |
| `AF_SRC_DIR` / `AF_DB_DIR` | 源码 / 库放在哪 | `./_targets/src`、`./_targets/db` |
| `AF_TARGET_MAP` | JSON 映射 `{"短名": "源码根目录"}` | 读 `core/config/targets*.yml` |
| `AF_SINKS_FS` / `_PATH` / `_HTTP` / `_DYNIMP` | 打开额外的 sink 组 | 关 |
| `AF_SINKS_EXTRA` | 是否启用 `source: extra` 的条目 | `1` |
| `AF_PATH_FILTER` | 路径过滤模式（`rel` = 相对项目） | `rel` |
| `AF_SOURCES_FILE` | 另一份不可信源头清单 | `core/config/sources.yml` |
| `AF_NO_DATAFLOW` | 关掉跨过程实参来源分析 | `0` |

---

## 仓库结构

```
core/      内核（静态前端 / 复核 / 可达性 / 污点追踪 / CodeQL 查询）
tools/     可复用工具（选择目标 / 下载 / 各项检查 / 自测）
app/       入口（scan.py 扫单个目标，run_all.py 扫一批）
demo/      故意有洞的示例项目，给 --demo 用
examples/  合成示例输出
```

---

## 致谢

CodeQL 前端与基线 sink 清单来自 **AgentFuzz**：

> Fengyu Liu, Yuan Zhang, Jiaqi Luo, Jiarun Dai, Tian Chen, Letian Yuan, Zhengmin Yu,
> Youkun Shi, Ke Li, Chengyuan Zhou, Hao Chen, Min Yang.
> *Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in
> LLM-based Agents.* 34th USENIX Security Symposium (USENIX Security '25), 2025, pp. 3767–3786.

`core/gen_ql.py` 就是从这个参考包重新生成查询的，`AF_PAPER_QL` 指的也是它。
`core/config/sinks.yml` 里 `source: extra` 的部分、可达性检查、参数贯通性检查，
以及 LLM 复核层，都是在基线之上加的东西。

---

## 许可证

MIT —— 见 [LICENSE](LICENSE)。

> ★ 请**只对你获得了授权测试的目标**使用。
