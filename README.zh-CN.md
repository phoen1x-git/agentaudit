# agentaudit

[English](README.md) | **中文**

<!-- CI 徽章。等仓库有地址之后，把下面两行的 OWNER/REPO 换成真实地址并去掉注释；
     第一次 workflow 跑完就会变绿。现在故意注释掉：指向一个还不存在的仓库，只会显示成裂图。

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
-->

**给 AI Agent 做代码审计。** 静态分析 + LLM 复核的扫描器：在 LLM / Agent 代码里找出危险调用点，
并且在**拿不准的时候直接说「我不知道」**。

输出的是**候选清单**，不是「已确认的漏洞清单」。

| | |
|---|---|
| 试一下 | `agentaudit scan --demo` —— 不用 CodeQL、不用 API key、不用下载 |
| 抓不到什么 | [LIMITATIONS.md](LIMITATIONS.md) —— 建议先读它，再决定要不要信下面任何一句话 |

---

## 它解决什么问题

危险调用（`eval`、`subprocess`、`open`、`requests` …）在 Agent 代码里到处都是，
传统污点分析会把它们**全部**标出来。但换个问题问，结论就完全不一样：

```python
# 是候选。危险调用？是。是漏洞吗？大概率不是。
handler = eval(spec_name)          # spec_name 来自本文件里的内置表
```

一个被标出来的调用点到底是不是真的，取决于三个问题，而污点分析只回答了第一个：

| # | 问题 | 谁来回答 |
|---|---|---|
| ① | 有没有危险调用？ | 静态分析 |
| ② | 它的实参**外部可控**吗？ | 本项目 |
| ③ | 这个实参**能一路活到 sink** 吗？ | 本项目 |

`agentaudit` 把 ② 和 ③ 做成可运行的检查，并且把「**复核层判不出来**」
当成一个**正经的可报结果**（`needs_human`），而不是用一个看起来很自信的猜测把它盖过去。

---

## 安装

需要 **Python 3.10+**。[CodeQL CLI](https://github.com/github/codeql-cli-binaries)（几百 MB）
是**可选的** —— 没有它就退回离线模式，查得少一些，但什么都不用装。

```bash
git clone <本仓库> && cd agentaudit
./scripts/setup.sh                 # 装依赖 + 下载 CodeQL CLI；或者只：
pip install -e .                   # 只装依赖，但会给你一条 `agentaudit` 命令
```

两种方式都能直接跑脚本（`python app/scan.py ...`）。做了可编辑安装之后还多一条统一入口：

```bash
agentaudit scan --demo
agentaudit explain out/round-demo --index 3
agentaudit serve out/round-demo
agentaudit --help
```

产物写进当前目录下的 `./out`；设了 `$AGENTAUDIT_HOME` 就写到那儿。
**不会往安装目录里写任何东西。**

### 冒烟测试

```bash
agentaudit selftest                # 等价于 python tools/run_selftests.py
agentaudit scan --demo             # 拿自带的示例项目跑一遍，出 13 条候选
```

两条都只要几秒钟，而且不需要装任何别的东西。**这两条过了，环境就是好的。**

### Docker

不想自己装 CodeQL 就用镜像（已经打进去了）：

```bash
docker build -t agentaudit .
docker run --rm agentaudit                                             # 扫自带示例
docker run --rm -v "$PWD/myproject:/scan/myproj:ro" \
    agentaudit --path /scan/myproj --tag myproj --out /scan/out
```

镜像的 entry point 是 `agentaudit scan`，所以上面那些参数和你本机敲的完全一样。
其它子命令要单独指定 entry point：

```bash
docker run --rm --entrypoint agentaudit agentaudit log
docker run --rm --entrypoint /opt/agentaudit/_tools/codeql/codeql agentaudit version
```

`Dockerfile` 是在一台**没有 Docker** 的机器上写的，所以**第一次构建就是验证**。
它是照着「要炸就炸在明处」写的 —— CodeQL CLI 会在**构建过程中被执行**，
布局不对就**直接让构建失败**，而不是产出一个「扫描器根本跑不起来」的镜像。
CI 每次 push 都会构建 + 冒烟测试这个镜像。

### 全部命令

| 命令 | 做什么 |
|---|---|
| `agentaudit interactive` | 交互菜单（不想记参数时用；直接敲 `agentaudit` 也会进） |
| `agentaudit scan` | 扫一个目标 —— `--demo`、`--path 目录`、`--repo 用户名/仓库名` |
| `agentaudit explain <轮次>` | 解释某条候选为什么被标出来 |
| `agentaudit serve <轮次>` | 在浏览器里看整轮（只绑本机） |
| `agentaudit report <轮次>` | 生成报告草稿 |
| `agentaudit index <轮次>` | 生成 HTML 清单页 |
| `agentaudit sarif <轮次>` | 把该轮导出成 SARIF 2.1.0 |
| `agentaudit round --tag 名字` | 按目标表跑一轮 |
| `agentaudit all --tag 名字` | 下载 → 扫描 → 出报告，可断点续跑 |
| `agentaudit selftest` | 跑规则自测 |
| `agentaudit validate` | 校验 `core/config/*.yml` |
| `agentaudit log` | 查看 / 导出本机的扫描统计 |

---

## 快速开始

一条命令就能扫 —— 不用先准备目标清单，也不用自己建库：

```bash
agentaudit scan --demo                  # 仓库里自带的示例项目
agentaudit scan --path ./myproject      # 扫本地已有的一个项目
agentaudit scan --repo owner/name       # 拉一个 GitHub 仓库来扫
```

### 或者用菜单

直接敲 `agentaudit`，终端里会出现这个：

```
  1  扫一个目标
  2  打开之前某一轮的结果
  3  跑规则自测
  4  校验规则配置
  5  看扫描统计（本地、只有统计量）
  6  列出所有命令
  0  退出
```

它会**把真正执行的命令行回显出来** —— 菜单是用来教你参数的，不是把参数藏起来。
另外**没有终端时（管道、CI）它会拒绝进入交互模式**，不会卡在那儿等输入。

### `out/round-<tag>/` 里有什么

| 文件 | 是什么 |
|---|---|
| `findings.tsv` | 候选表，一行一条 —— **这是主要产物** |
| `report_draft.md` | 报告草稿，一条候选一节 |
| `index.html` | 可排序 / 可搜索的候选清单页 |
| `agentaudit.sarif` | 候选清单导成 SARIF 2.1.0，可进 code-scanning 界面或编辑器 |
| `results.sarif` | CodeQL 前端自己的原始输出（仅 full 模式） |
| `meta.json` | 用的是哪种模式、开了哪些规则开关、花了多久 |

这里面的**每一条都是候选**。整条流水线**从不运行你的代码**，所以**没有任何一条是已确认的**。

---

## 读结果

`findings.tsv` 是原始表。下面三条命令让它变得能用。

### 这条为什么被标出来？

```bash
agentaudit explain out/round-x --index 3
```

会打印被标记那一行的上下文源码、能走到它的调用链、这条路上有哪些 if 守卫、
以及那个危险实参是从哪来的 —— **查不出来就明说「本次扫描没能确定」**。
**相信或否掉一条候选之前，先看这个。**

### 在浏览器里看整轮

```bash
agentaudit serve out/round-x
```

只绑 `127.0.0.1`、只服务那一个目录、关闭目录列表、路径穿越返回 404。

### 报告

`report_draft.md` 是自动生成的，它的开头会写明：里面的判定是 AI 辅助得出的，
**没有经过实跑验证**。[`examples/`](examples/) 里有一份完整的合成样例 ——
样例覆盖了扫描器区分出的四种结果：`vuln`、`not_vuln`（非外部可控）、
`not_vuln`（被校验拦住）、以及 **`needs_human`**（来源无法判定）。
最后一种才是重点：**只会输出 `vuln` / `not_vuln` 的扫描器，是在谎报自己的确定性。**

### 在编辑器或 code-scanning 界面里看

每次扫描都会写 `agentaudit.sarif`。它**只写相对路径** —— 没有绝对路径，也没有
`originalUriBaseIds` —— 所以从你机器上拿走的文件**带不走你的目录结构**。
所有结果的 level 一律是 `warning`，判定结果放在 `properties` 里，
因为读 SARIF 的工具看不到那些「这是候选、不是结论」的上下文。
已经判成 `not_vuln` 的行默认不导出，`agentaudit sarif --all` 可以带上。

---

## 帮我把它改得更好

**如果你愿意把扫描统计发给我，我会很感谢。** 它对你没有任何成本、里面没有一行代码，
而且它是**我自己拿不到的那样东西**：这个扫描器在我没见过的代码上是什么表现。
**一条在你的代码上会响、在我代码上从来不响的检查，是你最值得给我的东西。**

每次扫描会往 `./data/scan_log.jsonl` 本地追加一行：

| 会记录 | 永远不会记录 |
|---|---|
| 扫了多少文件、出了多少候选 | 源码，或者源码的任何片段 |
| 各检查、各判定的分布 | 文件路径、文件名 |
| 耗时、工具版本、规则配置的哈希 | 项目名，或任何能定位到它的信息 |
| 你的 Python 小版本号和操作系统种类 | 任何关于你个人的东西 |

```bash
agentaudit log                    # 看看你本机扫了什么
agentaudit log --export           # 导出一份小聚合，写到 scan_stats.json
agentaudit log --clear            # 删掉
```

**任何东西都不会被上传。** 这部分代码里**没有任何网络请求**，
所以它离开你机器的唯一途径，是**你自己把它拷出去**。
`--export` 会拿上面的表格再校验一次聚合结果，不通过就拒绝写出，
所以**先自己读一遍再决定**。

觉得没问题的话，开一个 [issue](https://github.com/OWNER/REPO/issues) 贴进去就行。
不想发也完全可以 —— **日志是你的**，`--no-log`（或 `AGENTAUDIT_NO_LOG=1`）可以整个关掉。

---

## 它的行为

在你相信任何一个数字之前，这几件事值得知道。

### 两种模式

| 模式 | 需要什么 | 能找出什么 |
|---|---|---|
| **full** | CodeQL CLI | CodeQL 查询**加上** AST 检查；写原始 SARIF |
| **offline** | 什么都不用 | 只有 AST 检查 |

没装 CodeQL 时会明确告诉你走了离线模式。用的是哪种模式会记在 `meta.json` 里、
也会印在报告开头 —— 因为**两种模式找到的东西不一样**。`--no-codeql` 可以强制走离线。

### LLM 复核默认**关**

它要花 API 额度，所以只在你要求时才跑：

```bash
agentaudit scan --path ./myproject --llm
```

开跑之前会先印出候选条数和硬上限（`AF_LLM_MAX_CNY`，默认 30 元），跑完报实际花费。
不加 `--llm` 就只有候选清单、没有判定 —— **报告会如实这么说**，不会暗示已经判过。

**实参来源不明（`arg_source=unknown`）的 `vuln` 会被降级成 `needs_human`。**
把同一条候选反复跑，表现不稳定的正是这一类 —— 它们的翻转率明显高于其它候选。
原始判定留在 `ai_reason` 和 `verdicts.json` 里，**没有丢东西**；
`--no-unknown-downgrade` 可以关掉这个行为，而轮次里会记录它是开还是关。

### 当门禁用

```bash
agentaudit scan --path ./myproject --fail-on any        # 报了候选就退 1
agentaudit scan --path ./myproject --llm --fail-on vuln # 只有判成 vuln 才退 1
agentaudit scan --path ./myproject --diff origin/main   # 只看改动过的文件
```

`--diff` 要求源码是一份 git 检出，用途是「**这个 PR 有没有引入新东西**」，
**不是**做全量审计。

### 跳过树里的某些部分

```bash
agentaudit scan --path ./big-repo --ignore 'vendor/**' --ignore '*/generated/*.py'
```

模式是相对源码根的 glob，并会写进轮次记录，这样两轮之间仍然可比。
**你排除掉的东西就是没扫过的东西** —— 所以如果 `vendor/` 被跳过了，
「`vendor/` 里没有候选」这句话**什么也不说明**。

### `scan` 的全部参数

| 参数 | 做什么 |
|---|---|
| `--demo` | 扫仓库自带的示例项目 |
| `--path 目录` | 扫本地一个目录 |
| `--repo 用户名/仓库名` | 拉一个 GitHub 仓库来扫 |
| `--project 名字` | 报告里显示的项目名（默认从路径推） |
| `--tag 名字` | 轮次目录名（默认自动生成） |
| `--out 目录` | 轮次写到哪（默认 `./out`） |
| `--llm` | 用 LLM 复核 —— **要花钱，所以默认关** |
| `--no-unknown-downgrade` | 实参来源不明时也保留 `vuln` 判定 |
| `--no-codeql` | 强制走离线模式 |
| `--lang en\|zh` | 报告语言（默认 `en`） |
| `--diff [REF]` | 只报自 `REF` 以来改动过的文件 |
| `--fail-on none\|any\|vuln` | 当门禁用，命中就退非零 |
| `--ignore GLOB` | 跳过匹配的路径（可重复） |
| `--serve` | 扫完直接起本地网页 |
| `--no-sarif` | 不写 `agentaudit.sarif` |
| `--no-log` | 不写本地扫描统计日志 |

---

## 它检查哪些东西

危险调用清单放在 **`core/config/sinks.yml`** —— 一个 YAML 文件、52 条危险调用规则，不是写死在代码里的。
`core/gen_ql.py` 读它并生成 CodeQL 查询，所以**加你自己的危险函数是改配置，不是改代码**。

| 组 | 例子 | 默认 |
|---|---|---|
| 基线 | `subprocess.run` / `Popen`、`os.system`、`requests.get/post/request`、`eval`、`exec`、`jinja2.from_string`、`*.execute(...)` | **开** |
| 数据库客户端 | 名字以 `conn` 结尾的接收者上的 `.query(...)` | **开** |
| 文件 I/O（`AF_SINKS_FS`） | `os.remove/unlink/rename/mkdir/chmod/...`、`shutil.move/rmtree/...` | 关 |
| 路径拼接（`AF_SINKS_PATH`） | `os.path.join`、`os.path.abspath` | 关 |
| HTTP 客户端（`AF_SINKS_HTTP`） | `httpx.get/post/...`、`httpx.Request`、`httpx.Client` | 关 |
| 动态派发（`AF_SINKS_DYNIMP`） | `importlib.import_module`、`__import__`、`import_module` | 关 |

默认关掉的组是因为**太吵**；打开它们是用精度换候选数量。开关值会记在每轮的 `meta.json` 里。

除了 sink，内核还会检查同一个文件里各端点的鉴权是否一致、
同一个函数里强弱两种写法是否共存、以及一个 sink 能不能从入口到达。

**加你自己的危险函数只要几行 YAML** —— 字段说明见
[CONFIGURING.md](CONFIGURING.md)，改完跑 `agentaudit validate` 检查一下。

---

## 它抓不到什么

这些都是**刻意的取舍，不是 bug**。完整版（包括分析**根本看不见**的那些模式、
以及它哪些沉默是有意义的）在 **[LIMITATIONS.md](LIMITATIONS.md)**。

- **只支持 Python。** 静态前端绑在 CodeQL 的 Python 包上。
- **复核层本身是抖的。** 同一条候选重跑，**相当一部分判定会变**。
  稳定得可疑的结果，通常是**缓存**造成的 —— 重新判的时候记得换 `--tag`。
- **`arg_source=unknown` 不可信。** 这个值的意思是「模型自己也不知道实参从哪来」；
  这类行默认被降级。
- **「没找到调用方」不等于「不可达」。** 只做了基于名字的匹配，
  所以跨文件派发和动态派发都会漏。
- **框架中介。** 实现落在 `site-packages` 而不是被扫的树里时，静态分析就停在 import 那一步。
- **离线模式查得更少。** 没有跨过程可达性，也没有框架建模。
- **重新生成 CodeQL 查询需要 AgentFuzz 参考包。** 只在重新生成时需要；
  已提交的 `core/ql/*.ql` 不装也能用（用 `AF_PAPER_QL` 指向它）。
- **每一条结论都需要人确认。** 这个工具产出的是候选，不是结论。

---

## 配置项

密钥一律从文件或环境变量读取，**从不提交**。

| 环境变量 | 用途 | 默认 |
|---|---|---|
| `DEEPSEEK_KEY_FILE` | LLM API key 文件路径 | `~/.deepseek_key` |
| `GITHUB_KEY_FILE` | GitHub token 文件路径（提高 API 额度） | `~/.github_token` |
| `AF_LLM_MAX_CNY` | **单次运行的硬上限**；到限即停并报数 | `30` |
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
| `AGENTAUDIT_HOME` | 产物（`out/`、`data/`）写到哪 | 当前目录 |
| `AGENTAUDIT_NO_LOG` | 设成 `1` 就不记扫描统计 | 未设置 |
| `AGENTAUDIT_ASCII` | 设成 `1` 时 banner 只用 ASCII 画 | 自动检测 |

---

## 它怎么工作

给要读代码的人，以及要**批量**扫而不是扫单个目标的人。

```
选择目标 -> 下载并建 CodeQL 库 -> 静态前端（CodeQL）
  -> 可达性筛选 -> 追入口 -> 参数贯通检查
  -> LLM 复核 -> 报告素材
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

`app/scan.py` 包的是同一套引擎。**要扫一整批目标时**，就按阶段手动跑：

```bash
# 1) 离线自测（免费）
agentaudit selftest

# 2) 选目标（需要 GitHub token）
python tools/target_screener.py fetch
python tools/target_screener.py screen

# 3) 下源码 + 建 CodeQL 库（可重跑；已完成的部分会跳过）
python tools/prepare_new_targets.py --status
python tools/prepare_new_targets.py

# 4) 跑一轮
agentaudit round --tag my-round --targets-file core/config/targets.yml

# 5) 出报告草稿和 HTML 清单页
agentaudit report out/round-my-round --lang en
agentaudit index  out/round-my-round --lang en
```

> **注意花费。** 复核阶段会消耗 LLM 额度。脚本会**事先印出预估花费**，
> `AF_LLM_MAX_CNY` 到限会**硬停**。

---

## 仓库结构

```
core/            内核（静态前端 / 复核 / 可达性 / 污点追踪 / CodeQL 查询）
core/config/     规则：sinks.yml、sources.yml、filters.yml —— 见 CONFIGURING.md
tools/           可复用工具（选择目标 / 下载 / 各项检查 / 自测）
app/             入口（scan.py、run_all.py、explain.py、serve.py、cli.py）
demo/            故意有洞的示例项目，给 --demo 用
examples/        合成示例输出
tests/           CI 跑的测试
scripts/         setup.sh
```

## 文档

| | |
|---|---|
| [CONFIGURING.md](CONFIGURING.md) | 规则字段说明，以及怎么加你自己的危险函数 |
| [LIMITATIONS.md](LIMITATIONS.md) | 它抓不到什么 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 怎么跑测试、怎么扩 |
| [CHANGELOG.md](CHANGELOG.md) | 改了什么 |

---

## 作者的话

我是在做 AI Agent 安全的时候写它的。真正卡住我的**不是「找到一个危险调用」**，
而是**找到之后该怎么判它**：同一条候选让模型看两遍，答案不一定一样。
一个把这件事藏起来的工具，比一个会漏东西的工具更糟 ——
因为你分不清它的**哪条**输出能信。

所以我给它定的原则很窄：**这里任何东西都不许比它实际知道的更确定。**
`needs_human` 是一个**正经结论**；查不出来的东西就印「未确定」，**不猜**；
每份报告都会写明：**没有经过实跑验证**。
[`LIMITATIONS.md`](LIMITATIONS.md) 是刻意维护着的 ——
因为**一个只列自己强项的工具，等于什么都没告诉你**。

如果你跑了它、发现它错了 —— **正反两个方向都算** —— 那是你能给我的最有用的东西。
谢谢你看到这里。

---

## 致谢

CodeQL 前端和基线 sink 清单来自 **AgentFuzz**：

> Fengyu Liu, Yuan Zhang, Jiaqi Luo, Jiarun Dai, Tian Chen, Letian Yuan, Zhengmin Yu,
> Youkun Shi, Ke Li, Chengyuan Zhou, Hao Chen, Min Yang.
> *Make Agent Defeat Agent: Automatic Detection of Taint-Style Vulnerabilities in
> LLM-based Agents.* 34th USENIX Security Symposium (USENIX Security '25), 2025, pp. 3767–3786.

`core/gen_ql.py` 从那个参考包重新生成查询，所以有 `AF_PAPER_QL` 这个变量。
`core/config/sinks.yml` 里所有 `source: extra` 的条目、可达性检查、参数贯通检查、
以及复核层，都是在这个基线之上加的东西。

---

## 许可证

MIT —— 见 [LICENSE](LICENSE)。

> 请只对**你有授权测试的**目标使用。
