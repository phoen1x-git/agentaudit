# agentaudit

[English](README.md) | **中文**

<!-- CI 徽章。等仓库有地址之后，把下面两行的 OWNER/REPO 换成真实地址并去掉注释；
     第一次 workflow 跑完就会变绿。现在故意注释掉：指向一个还不存在的仓库，只会显示成裂图。

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
-->

这是一个给 AI Agent 项目做代码审计的工具。它读 LLM / Agent 的代码，找出危险调用点，
再判断每一个调用点的参数是不是真能从外面控制、能不能一路传到这个调用点。
判断不出来的时候，它写「不知道」，而不是给一个猜出来的结论。

它输出的是一份**候选清单**，不是「已确认的漏洞清单」。每一条都还需要人再看一遍。

| | |
|---|---|
| 试一下 | `agentaudit scan --demo`，不需要 CodeQL、不需要 API key、不需要下载 |
| 抓不到什么 | [LIMITATIONS.md](LIMITATIONS.md)，它查不到的东西都列在那里 |

---

## 它解决什么问题

Agent 项目里到处都是危险调用：`eval`、`subprocess`、`open`、`requests` 等等。
这些调用大多是必要的，要执行命令就得调 `subprocess`。所以传统的污点分析一跑，
会把它们全部标出来，结果就是一大堆「这里有个危险调用」，很难用。

真正的问题不是「有没有危险调用」，而是下面三个：

```python
# 这是危险调用，但它不是漏洞：spec_name 来自本文件里的一个内置表，外面控制不了
handler = eval(spec_name)
```

| # | 问题 | 谁来回答 |
|---|---|---|
| ① | 有没有危险调用？ | 静态分析，现有工具都能答 |
| ② | 它的参数能不能从外面控制？ | 这个工具 |
| ③ | 这个参数能不能一路传到调用点？ | 这个工具 |

`agentaudit` 做的就是第 ② 和第 ③ 件事，把这两件事变成可运行的检查。
判断不出来的时候，它输出 `needs_human`（需要人来判断），这是它的一个正常结论，不是失败。

---

## 安装

需要 Python 3.10 或更高版本。[CodeQL CLI](https://github.com/github/codeql-cli-binaries)
是可选的，它有几百 MB。不装的话工具会退回离线模式，查得少一些，
但除了 PyYAML 之外不需要装任何东西。

```bash
git clone <本仓库> && cd agentaudit
./scripts/setup.sh                 # 装依赖 + 下载 CodeQL CLI；或者只：
pip install -e .                   # 只装依赖，但会给你一条 `agentaudit` 命令
```

两种装法都能直接跑脚本（`python app/scan.py ...`）。用 `pip install -e .` 装过之后，
还会多出一个统一的命令：

```bash
agentaudit scan --demo
agentaudit explain out/round-demo --index 3
agentaudit serve out/round-demo
agentaudit --help
```

产物写在当前目录的 `./out` 下；如果设了 `$AGENTAUDIT_HOME`，就写到那里。
安装目录里不会写进任何东西。

### 冒烟测试

```bash
agentaudit selftest                # 等价于 python tools/run_selftests.py
agentaudit scan --demo             # 拿自带的示例项目跑一遍，出 13 条候选
```

两条都只要几秒钟，而且不需要装任何别的东西。这两条过了，环境就没问题。

### Docker

不想自己装 CodeQL 的话可以用镜像，镜像里已经带了：

```bash
docker build -t agentaudit .
docker run --rm agentaudit                                             # 扫自带示例
docker run --rm -v "$PWD/myproject:/scan/myproj:ro" \
    agentaudit --path /scan/myproj --tag myproj --out /scan/out
```

镜像的入口（entry point）是 `agentaudit scan`，所以上面那些参数和你本机敲的完全一样。
其它子命令要单独指定入口：

```bash
docker run --rm --entrypoint agentaudit agentaudit log
docker run --rm --entrypoint /opt/agentaudit/_tools/codeql/codeql agentaudit version
```

这个 Dockerfile 是在一台没有 Docker 的机器上写的，所以第一次构建就是第一次验证。
它被写成「出错就尽早出错」：CodeQL CLI 会在构建过程中被执行一次，如果目录结构不对，
构建直接失败，而不是产出一个扫描器根本跑不起来的镜像。
CI 每次 push 都会构建它并做一遍冒烟测试。

### 全部命令

| 命令 | 做什么 |
|---|---|
| `agentaudit interactive` | 交互菜单（不想记参数时用；直接敲 `agentaudit` 也会进） |
| `agentaudit scan` | 扫一个目标：`--demo`、`--path 目录`、`--repo 用户名/仓库名` |
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
| `agentaudit targets` | 找并筛 GitHub 上的目标（给批量扫描用，不是单仓库） |

---

## 快速开始

一条命令就能扫，不用先准备目标清单，也不用自己建库：

```bash
agentaudit scan --demo                  # 仓库里自带的示例项目
agentaudit scan --path ./myproject      # 扫本地已有的一个项目
agentaudit scan --repo owner/name       # 拉一个 GitHub 仓库来扫
```

要一次扫很多个仓库的话，走的是另一条路：先筛候选，再下源码、建库，然后成批扫描。
完整步骤在下面「它怎么工作」里的 [批量扫描](#scanning-a-batch) 一节。

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

它会把你选的那一步真正执行的命令行打印出来。菜单的作用是让你记住参数，
不是把参数藏起来。另外，如果在没有终端的地方运行（管道、CI），
它会拒绝进入交互模式，而不是卡在那里等输入。

### `out/round-<tag>/` 里有什么

| 文件 | 是什么 |
|---|---|
| `findings.tsv` | 候选表，一行一条，主要产物在这里 |
| `report_draft.md` | 报告草稿，一条候选一节 |
| `index.html` | 可排序 / 可搜索的候选清单页 |
| `agentaudit.sarif` | 候选清单导成 SARIF 2.1.0，可进 code-scanning 界面或编辑器 |
| `results.sarif` | CodeQL 前端自己的原始输出（仅 full 模式） |
| `meta.json` | 用的是哪种模式、开了哪些规则开关、花了多久 |

这里面的每一条都是候选。整条流水线**不运行被扫的代码**，只是读它，
所以没有任何一条是已确认的。

---

## 读结果

`findings.tsv` 是原始表。读它的时候，下面三条命令最常用。

### 这条为什么被标出来？

```bash
agentaudit explain out/round-x --index 3
```

它会打印被标记那一行的上下文源码、能走到它的调用链、这条路上有哪些 if 守卫，
以及那个危险实参是从哪来的。查不出来的话，它会明说「本次扫描没能确定」。
在相信或否掉一条候选之前，先跑这个。

### 在浏览器里看整轮

```bash
agentaudit serve out/round-x
```

只绑 `127.0.0.1`、只服务那一个目录、关闭目录列表、路径穿越返回 404。

### 报告

`report_draft.md` 是自动生成的，开头会写明：里面的判定由 AI 辅助得出，没有经过实跑验证。
[`examples/`](examples/) 里有一份合成样例，覆盖了扫描器区分出的四种结果：
`vuln`、`not_vuln`（非外部可控）、`not_vuln`（被校验拦住）、以及 `needs_human`（来源无法判定）。
最后一种是关键。只回答「是」或「不是」、从来不说「不知道」的扫描器，
等于在假装自己比实际更有把握。

### 在编辑器或 code-scanning 界面里看

每次扫描都会写 `agentaudit.sarif`。里面只写相对路径，没有绝对路径，也没有
`originalUriBaseIds`，所以这个文件拿到别的机器上，不会带出你的目录结构。
所有结果的 level 一律是 `warning`，判定结果放在 `properties` 里，
因为读 SARIF 的工具看不到那些「这是候选、不是结论」的上下文。
已经判成 `not_vuln` 的行默认不导出，`agentaudit sarif --all` 可以带上。

---

## 帮我把它改得更好

如果你愿意把扫描统计发给我，我会很感谢。它对你没有任何成本，里面也没有一行代码。
而且它是我自己拿不到的东西：这个扫描器在我没见过的代码上是什么表现。
一条在你的代码上会响、在我代码上从来不响的检查，是最值得给我的东西。

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

**任何东西都不会被上传。** 这部分代码里没有任何网络请求，
所以它离开你机器的唯一途径，是你自己把它拷出去。
`--export` 会拿上面的表格再校验一次聚合结果，不通过就拒绝写出，
所以先自己读一遍再决定。

觉得没问题的话，开一个 [issue](https://github.com/OWNER/REPO/issues) 贴进去就行。
不想发也完全可以，日志是你的，`--no-log`（或 `AGENTAUDIT_NO_LOG=1`）可以整个关掉。

---

## 它的行为

在你相信任何一个数字之前，这几件事值得知道。

### 两种模式

| 模式 | 需要什么 | 能找出什么 |
|---|---|---|
| **full** | CodeQL CLI | CodeQL 查询**加上** AST 检查；写原始 SARIF |
| **offline** | 什么都不用 | 只有 AST 检查 |

没装 CodeQL 时，它会明确告诉你走了离线模式。用的是哪种模式会记在 `meta.json` 里，
也会印在报告开头，因为两种模式找到的东西不一样。`--no-codeql` 可以强制走离线。

### 模型判断默认关闭

它要花 API 额度，所以只在你要求时才跑：

```bash
agentaudit scan --path ./myproject --llm
```

开跑之前会先印出候选条数和硬上限（`AF_LLM_MAX_CNY`，默认 30 元），跑完再报实际花费。
不加 `--llm` 就只有候选清单、没有判定。报告会如实说明这一点，不会暗示已经判过。

实参来源不明（`arg_source=unknown`）的 `vuln` 会被降级成 `needs_human`。
这类正是表现不稳定的那些：同一条候选反复跑，它们的翻转率明显高于其它候选。
原始判定留在 `ai_reason` 和 `verdicts.json` 里，没有丢东西。
`--no-unknown-downgrade` 可以关掉这个行为，轮次里会记录它是开还是关。

### 当门禁用

```bash
agentaudit scan --path ./myproject --fail-on any        # 报了候选就退 1
agentaudit scan --path ./myproject --llm --fail-on vuln # 只有判成 vuln 才退 1
agentaudit scan --path ./myproject --diff origin/main   # 只看改动过的文件
```

`--diff` 要求源码是一份 git 检出，用途是回答「这个 PR 有没有引入新东西」，
不是做全量审计。

### 跳过树里的某些部分

```bash
agentaudit scan --path ./big-repo --ignore 'vendor/**' --ignore '*/generated/*.py'
```

模式是相对源码根的 glob，会写进轮次记录，这样两轮之间仍然可比。
排除掉的东西就是没扫过的东西，所以如果 `vendor/` 被跳过了，
「`vendor/` 里没有候选」这句话什么也说明不了。

### `scan` 的全部参数

| 参数 | 做什么 |
|---|---|
| `--demo` | 扫仓库自带的示例项目 |
| `--path 目录` | 扫本地一个目录 |
| `--repo 用户名/仓库名` | 拉一个 GitHub 仓库来扫 |
| `--project 名字` | 报告里显示的项目名（默认从路径推） |
| `--tag 名字` | 轮次目录名（默认自动生成） |
| `--out 目录` | 轮次写到哪（默认 `./out`） |
| `--llm` | 用 LLM 判断，要花钱，所以默认关 |
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

危险调用清单放在 `core/config/sinks.yml` 里，一个 YAML 文件、52 条危险调用规则，
不是写死在代码里的。`core/gen_ql.py` 读它并生成 CodeQL 查询，
所以加一条你自己的危险函数是改配置，不是改代码。

| 组 | 例子 | 默认 |
|---|---|---|
| 基线 | `subprocess.run` / `Popen`、`os.system`、`requests.get/post/request`、`eval`、`exec`、`jinja2.from_string`、`*.execute(...)` | **开** |
| 数据库客户端 | 名字以 `conn` 结尾的接收者上的 `.query(...)` | **开** |
| 文件 I/O（`AF_SINKS_FS`） | `os.remove/unlink/rename/mkdir/chmod/...`、`shutil.move/rmtree/...` | 关 |
| 路径拼接（`AF_SINKS_PATH`） | `os.path.join`、`os.path.abspath` | 关 |
| HTTP 客户端（`AF_SINKS_HTTP`） | `httpx.get/post/...`、`httpx.Request`、`httpx.Client` | 关 |
| 动态派发（`AF_SINKS_DYNIMP`） | `importlib.import_module`、`__import__`、`import_module` | 关 |

默认关掉的几组是因为太吵。打开它们，是用精度换候选数量。开关值会记在每一轮的 `meta.json` 里。

除了这些危险调用，内核还会检查三件事：同一个文件里各端点的鉴权是否一致、
同一个函数里安全的写法和不安全的写法是否并存、以及一个危险点能不能从入口到达。
（代码里管「危险点」叫 `sink`，`AF_SINKS_FS` 这类开关的组名就是从它来的。）

加你自己的危险函数只要几行 YAML。字段说明见
[CONFIGURING.md](CONFIGURING.md)，改完跑 `agentaudit validate` 检查一下。

---

## 它抓不到什么

这些都是刻意的取舍，不是 bug。完整版在 [LIMITATIONS.md](LIMITATIONS.md)，
里面包括分析根本看不见的那些模式，以及它哪些沉默是有意义的。

- **只支持 Python。** 静态前端绑在 CodeQL 的 Python 包上。
- **模型判断这一层本身不稳定。** 同一条候选重跑，相当一部分判定会变。
  结果稳定得可疑，通常是缓存造成的，所以重新判的时候记得换 `--tag`。
- **`arg_source=unknown` 不可信。** 这个值的意思是「模型自己也不知道实参从哪来」，
  这类行默认被降级。
- **「没找到调用方」不等于「不可达」。** 这里只做基于名字的匹配，
  跨文件派发和动态派发都会漏。
- **框架中介。** 实现落在 `site-packages` 而不是被扫的树里时，静态分析就停在 import 那一步。
- **离线模式查得更少。** 没有跨过程可达性，也没有框架建模。
- **重新生成 CodeQL 查询需要 AgentFuzz 参考包。** 只有重新生成时才需要；
  已提交的 `core/ql/*.ql` 不装也能用（用 `AF_PAPER_QL` 指向它）。
- **每一条结论都需要人确认。** 这个工具产出的是候选，不是结论。

---

## 配置项

密钥一律从文件或环境变量读取，从不提交。

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
| `AF_SOURCES_FILE` | 在默认清单之外**额外叠加**的不可信源头 | `core/config/sources.yml` |
| `AF_NO_DATAFLOW` | 关掉跨过程实参来源分析 | `0` |
| `AGENTAUDIT_HOME` | 产物（`out/`、`data/`）写到哪 | 当前目录 |
| `AGENTAUDIT_NO_LOG` | 设成 `1` 就不记扫描统计 | 未设置 |
| `AGENTAUDIT_ASCII` | 设成 `1` 时 banner 只用 ASCII 画 | 自动检测 |

完整清单在 [CONFIGURING.md](CONFIGURING.md)，包括模型判断那一层的开关。
有测试守着：加了新开关却没写进文档，会直接失败。

---

## 它怎么工作

这一节给两种人看：要读代码的人，和要批量扫而不是只扫一个仓库的人。

单个目标走四个阶段，`agentaudit scan` 会把四个都跑完：

| 阶段 | 在哪 | 做什么 |
|---|---|---|
| 静态前端 | `core/static_frontend.py` | 建 CodeQL 库、跑 `core/ql/` 里的查询、解析 SARIF |
| 强弱写法 | `core/duality.py` | 同一个函数里，同一件事一行写得安全、一行写得不安全 |
| LLM 复核 | `core/llm_judge.py` | 五个维度：`verdict` / `by_design` / `scope_exceeds` / `arg_source` / `guards_real` |
| 报告素材 | `app/make_report.py`、`app/make_index.py`、`tools/to_sarif.py` | 报告草稿、可排序清单页、SARIF |

另外两个横跨在上面：`core/consistency.py` 判断「证据支持不了什么」并拒绝报它，
`core/cfg.py` 管规则配置。`core/gate.py`（这个目标值不值得扫）和
`core/upstream.py`（是不是已经有人报过）只在批量路径里用。

<a id="scanning-a-batch"></a>

### 批量扫描

批量这段路有两个又慢又能续跑的阶段：随时可以停、可以重跑，做完的部分会跳过。

```bash
# 1) 先攒一份候选清单（需要 GitHub token，要几分钟）
agentaudit targets fetch        # -> data/target_pool/pool.json
agentaudit targets screen       # -> data/target_pool/screened.json

# 2) 挑出你要的写进批文件，然后下源码 + 建库
python app/prepare_targets.py data/target_pool/batch1.json

# 3) 扫这批，然后出报告
agentaudit round  --tag my-round --targets-file core/config/targets.yml
agentaudit report out/round-my-round
agentaudit index  out/round-my-round
```

`agentaudit all --tag my-round --batch data/target_pool/batch1.json --targets-file
core/config/targets.yml` 可以把上面这些串起来，已经做完的会跳过。

筛选时会排除你已经看过的仓库，这是「还没看过」这句话有意义的前提。
那份名单放在 `core/config/known_targets.yml`，不随仓库发布，把示例复制一份自己填。
它做成文件而不是代码里的常量，是因为一份真实仓库清单，透露的关于写它的人的信息，
比关于这个工具的信息更多。

> **注意花费。** 模型判断这一阶段会消耗 LLM 额度。脚本会事先印出预估花费，
> `AF_LLM_MAX_CNY` 到限会硬停。

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

我是在做 AI Agent 安全的时候写它的。真正卡住我的不是「找到一个危险调用」，
而是找到之后该怎么判它：同一条候选让模型看两遍，答案不一定一样。
一个把这件事藏起来的工具，比一个会漏东西的工具更糟，因为你分不清它的哪条输出能信。

所以我给它定的原则很窄：这里任何东西都不许比它实际知道的更确定。
`needs_human` 是一个正经结论；查不出来的东西就写「未确定」，不猜；
每份报告都会写明没有经过实跑验证。
[`LIMITATIONS.md`](LIMITATIONS.md) 是刻意维护的，因为一个只列自己强项的工具，
等于什么都没告诉你。

如果你跑了它、发现它错了（正反两个方向都算），那是你能给我的最有用的东西。
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
以及模型判断那一层，都是在这个基线之上加的东西。

---

## 许可证

MIT 许可证，见 [LICENSE](LICENSE)。

> 请只对**你有授权测试的**目标使用。
