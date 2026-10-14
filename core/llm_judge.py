"""内核 · LLM 判定层（开关 llm-judge）。

输入：一条 Finding（sink 调用点 + 所在函数源码 + 调用链 + 路径上的 if）
输出：结构化结论（危险动作 / 实参来源 / 守卫是否真实 / 判定 + 置信度 + 证据）

★★ 三条铁律
  ① 这是 **AI 复核**，不是人工核实。字段名一律 ai_verdict / ai_*，
     不许出现 confirmed / human-verified。
  ② LLM 只做分类，不做最终结论；**信息不足就判 needs_human**，不许硬给。
  ③ 判定尺度写死在 prompt 里（温度 0 + 缓存），否则数字每次都不一样。

★ 复用 `tools/llm_client.py`（缓存 / 成本记账 / 抗截断 JSON），不重造。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import srcctx as SC
from . import finding as F

# 复用现有客户端（零依赖、带缓存与记账）
_TOOLS = Path(__file__).resolve().parent.parent / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
import llm_client as LC  # noqa: E402

RUBRIC = """你是 Agent 项目漏洞判定的**复核员**（AI 复核，不是人工确认）。

背景：Agent 项目里，**大模型的输出**（LLM 生成的代码/SQL/参数）会被程序拿去执行。
静态分析已经找到一批「危险调用点」，并给出：该调用所在的函数源码、到达它的调用链、
以及调用链上压着的若干条件判断。★ 静态分析**没有**证明数据流，你看到的只是"可达"。

你的任务：判断这个危险调用的**实参**，是否可能来自不可信来源，以及守卫是否算真实防护。

★★ 先答【第四层】——它最容易被跳过，但决定前面三层算不算数：

第四层 · 这到底是不是「设计功能」？
  这个危险调用，是不是这个项目**本来就应该做**的事？
  - 代码解释器 / 代码执行工具 → **本来就该执行 LLM 生成的代码**（这是卖点，不是漏洞）
  - 数据库 / 问数 Agent → **本来就该执行 LLM 生成的 SQL**（同理）
  - 联网搜索工具 → 本来就该按 LLM 给的词发请求（除非能指向任意内网地址）
  ★ 对这类「设计功能」：**只有能证明它超出预期范围**才算 vuln，例如——
     该有沙箱却没有、能在宿主机或宿主任意文件上执行、
     能触达内网任意地址（不是固定主机/域名白名单）、
     本该只读却变成可写可执行。
  ★ 但如果这个危险调用**不是**该模块的设计用途（例：一个纯 HTTP 封装被喂了任意 URL，
    一个数据清洗模块里冒出来的 exec），那它是真问题，按前三层判。
  → by_design：yes（是设计功能）/ no（不是）/ unclear

★★ scope_exceeds 的判定约定（★ 写死，按此执行，**不要每次自己重新权衡**）
   ★★ 2026-10-09 改。改的原因：原措辞是"拿不到超出范围的证据时，判 not_vuln 或 needs_human"
      —— 给了**两个**选项、又没定义"什么算证据"，实测导致同一条 finding 重复判会翻
      。现在收敛成唯一答案。

   **只看本调用点所在函数的代码**（不看别的文件、不看运行环境、不猜调用方）：
   - `yes`  ← 在本函数体内**直接看到**：不可信内容被原样交给危险动作，
             且本函数内**没有任何**针对它的校验/隔离。
   - `no`   ← 在本函数体内能看到确实有校验/隔离（白名单、正则、参数绑定、转义、限制长度等）。
   - `unclear` ← 判断依据在**给定代码之外**（沙箱/白名单配置在别的文件、调用方、或部署环境里）。
              ★ **不许把"我没看到"当成"不存在"。**
   ★ 判 `unclear` 时，`ai_verdict` **必须取 needs_human**（不再在 not_vuln / needs_human 之间二选一）。
   ★ 必须在 `scope_exceeds_evidence` 里写出你依据的是**哪一行代码**；依据不在给定代码里，
     就写"依据在给定代码之外"，并判 unclear。

然后按三层回答，不要跳层：

第一层 · 危险动作与危险实参
  这个调用做什么（执行代码/执行SQL/发HTTP/起子进程/读文件/其他）？
  危险的是**哪个实参**（写出源码里的变量名）。

第二层 · 实参来自哪
  顺着所在函数体往上找那个变量怎么来的：
  - 来自函数参数？→ 看调用链/入口函数，判断上层有没有把 LLM 产出传进来
  - 来自 LLM 客户端 / 模型返回 / 工具入参 / 记忆？
  - 是写死常量 / 来自配置？→ 通常不算
  ★ 只依据**给你的代码**判断；关键代码没给到你，就标 unknown，不要猜。
  ★★ 但若上下文里给了【静态数据流给出的实参来源】，**以它为准，不要再自己猜**：
     - "可追溯到 **param** → `X` @ f.py:12"：说明实参**来自函数参数** →
       arg_source **不要**填 constant / config（它不是写死的）。
       更像 user_input 还是 llm_output，看参数名与函数用途；仍判不准就填 unknown。
     - "可追溯到 **web-request / stdin / argv**" → arg_source 填 **user_input**。
     - "可追溯到 **llm-client**" → arg_source 填 **llm_output**。
     - "追不到任何源头（local）" → 倾向于 **constant** 或 **config**（仍要结合代码看）。
     - "（本条没有数据流证据）" → 按原规则判断，不确定就 unknown。
     ★ 数据流**只回答"实参从哪来"**，不回答"这算不算漏洞"；第四层与守卫层照旧。

  ★★ 若上下文里还给了【实参来源所在函数的源码】—— **先读它，再下结论**：
     那个函数就是**接住这个值**的地方，真正的校验（白名单 / 正则 / 参数绑定 / 转义）
     通常就写在它体内。例：值追到 `param catalog`，而那个函数里写着
     `_assert_allowed_identifier(catalog, VALID_CATALOGS, "catalog")` → **这就是真防护**。
     · 在它体内看到针对**本值**的校验 → **guards_real 填 yes**（别再说"依据在代码之外"）
     · 看到的是在拦别的东西（判空 / 判环境 / 打日志）→ 不算防护
     · 确实一行针对本值的校验都没有 → guards_real 填 no
     · 它只是把值继续往下传（本函数内既无校验、也无危险动作）→ 才判 unclear
     ★ 这段源码**不是新规则**，是把原本就在代码里的证据补给你；该判什么仍按上面的尺度。

第三层 · 守卫算不算真防护
  调用链上压着的 if：
  - 在**校验实参**（白名单/正则/长度/转义）→ 算防护
  - 在**做别的事**（判空/判环境/判偏好）→ 不算
  ★ 「有 if」≠「有防护」。

只输出一个 JSON：
{
  "by_design": "yes|no|unclear",
  "scope_exceeds": "yes|no|unclear",
  "by_design_evidence": "一句话",
  "sink_action": "exec_code|exec_sql|http|subprocess|file|other",
  "danger_arg": "危险实参的变量名",
  "arg_source": "llm_output|user_input|tool_arg|memory|config|constant|unknown",
  "arg_source_evidence": "一句话，引用你看到的具体代码",
  "guards_real": "yes|no|unclear",
  "guards_evidence": "一句话",
  "ai_verdict": "vuln|not_vuln|needs_human",
  "confidence": 0.0,
  "one_line": "一句话结论"
}

尺度（照此，不放宽也不收紧）：
- ai_verdict=vuln       ：(by_design=no 且 arg_source 不可信 且 guards_real=no)
                         或 (by_design=yes 且 scope_exceeds=yes)
- ai_verdict=not_vuln   ：arg_source 是 constant/config；或 guards_real=yes；
                         或 by_design=yes 且 scope_exceeds=no
- ai_verdict=needs_human：代码不足以判断（如实参来源/沙箱情况在你没看到的文件里）——★ 别硬给
- confidence 如实给；信息不足就给低分，**不要为了给结论而虚报高分**。

★ **所有文字字段一律用中文填写**（代码片段、变量名按原文照抄即可）。
  审阅页是给中文读者看的，出现英文结论等于没写。"""


# ★★ max_tokens 策略：**按需给额度**（2026-10-10）
#   背景：给 2000 时约 4.5% 的条目输出被截断（判定变 `error`，甚至会**假性抹掉 vuln**）；
#        但全局拉到 5000 的代价是 **耗时 ×3.4（13→44 s）、成本 ×2.1** ——
#        因为推理模型拿到大额度就写更长的思考，是**输出 token 变多**，不是输入变多。
#   做法：默认 2000（`ask_json` 内部失败还会加成到 4000）；**只有确实失败时**才升配到 8000 重试。
#   ★★ 不做"热条目记忆"：实测截断**有随机性** —— 同一条 `verify_watchman...:547`
#      在 v1 的 A/B 两轮都截断，隔一会儿单独跑却用 2000 就过了。
#      记下来会让这条以后**每次都**用大额度，反而更贵更慢（过拟合到一个随机现象上）。
MT_DEFAULT = 2000
MT_BIG = 8000

# ★★ 可选规则补丁（开关 AF_JUDGE_OPARG=1，**默认关**）——  §四②
#   背景：batch3 里那条唯一的 `vuln` 是误报 —— `get_document_content.py` 的
#   `requests.get(url)`，而 `url` 来自**CLI 参数** `-u/--api-url`。跑这个 CLI 的人
#   自己就是操作者，他本来就能访问自己的网络 —— 这不是 SSRF。
#   根因：判定层把"程序自己的 CLI 参数"当成了不可信输入。
#   ★ 做成**可开关**而不是直接改：改规则会同时动"稳定性"和"刻度"，
#     必须能 A/B 对照，所以默认行为一字不改。
OPARG_BLOCK = """

★★ 补充规则（本条已启用）：什么叫「不可信输入」
  **同一个进程的操作者自己提供的输入，不算不可信输入** —— 跑这个程序的人本来就是操作者：
    · 命令行参数（sys.argv / argparse / click / typer 的选项）
    · 本进程自己的环境变量（os.environ 里项目定义的）
    · 本地交互输入 / 本地配置文件里由操作者填的值
  → 这类值 **arg_source 填 `config`**（来自配置文件）或 `unknown`，**不得据此判 vuln**。
  ★ 只有能说明这些值来自**另一个主体**时才算不可信：服务器接收的 HTTP 请求体/查询参数、
    被调用的工具入参、上游服务返回、LLM 产出。
  ★ 自检一句："**是谁在控制这个值？**" —— 若答案是"运行这个程序的人自己"，就不是漏洞。
"""

# ★★ 可选规则补丁（开关 AF_JUDGE_REPOCFG=1，**默认关**）——  / 
#   背景：upstream issue（**外部人报的真洞**）在现有 rubric 下被判 `not_vuln`，理由是
#   "base_url 来自本地 provider 配置（非 LLM/外部不可信输入）" ——
#   ★ 判定层没错，是「配置」这个词把**两种性质相反**的东西混成了一种：
#     · 操作者自己的配置（~/.config、自己的 CLI 参数）→ 不算不可信输入；
#     · **随仓库一起 clone 下来的项目内配置文件**（`.sampleproj.json` 等）→
#       控制它的是**仓库作者**，运行者只是"打开了别人的项目" → **算不可信输入**。
#   实测：加上这段后，同一条从 `not_vuln` 变成 `needs_human`，且理由变成
#   正确的问题（"取决于该 config 来自运行者自身配置还是仓库内配置文件"）。
#   ★ 仍做成**可开关**：改规则会同时动"刻度 + 稳定性"，必须能 A/B。
REPOCFG_BLOCK = """

★★ 补充规则（本条已启用）：什么叫「来自配置」—— 分两种，可信度正好相反

  「配置」**不是一种来源**，判定时必须先分清是哪一种：
  - `operator_config`（**操作者自己的**）：`~/.config/…`、操作者自己的环境变量、
    他自己在命令行上敲的选项。
    → 控制它的人 = **运行这个程序的人** → **不算不可信输入** → arg_source 填 `config`。
  - `repo_config`（★ **随被处理的那个项目一起拿到的文件**）：项目目录内部的
    `*.json` / `*.toml` / `*.yaml` / `.env`，例如 `.sampleproj.json`、`.mcp.json`、
    `pyproject.toml` 里的配置节、仓库自带的 `config.yaml`。
    → ★ 控制它的人 = **那个仓库的作者**，而运行者只是"clone 了别人的项目 / 打开了别人的目录"，
      他**并不知道里面写了什么** → **算不可信输入** → arg_source 填 **`user_input`**。

  ★ 自检一句："**这个值写在哪、谁有权改它？**"
    · 写在运行者自己主目录 / 他自己敲的命令行里 → operator_config → 不算洞；
    · 写在**被处理的那个仓库内部** → repo_config → **算**。

  ★★ 特别注意「分层覆盖 / 深合并」这种模式（这是最容易漏的一类）：
    当配置是**多层合并**、且**靠后的层可以覆盖靠前的层**，而其中一层来自项目内文件时——
    攻击者只需在项目内文件里**只写要劫持的那一项**（例如 `base_url` / `endpoint` / `mcp.servers`），
    **凭据（api_key / token）仍从操作者的全局配置或环境变量继承** ——
    结果就是"**把操作者的凭据发到攻击者指定的端点**"。
    → 判这类时**不要**因为"api_key 来自操作者配置"就判 not_vuln：
      **凭据的来源和去向要分开看**，劫持的是**去向**。
"""


# ★★ 可选规则补丁（开关 AF_JUDGE_SCOPE2=1，**默认关**）—— 
#    为什么加： 实测 37 条里 9 条结论翻转，**逐轮打标后 9/9 都由
#    「scope_exceeds 的语义边界没被定义」引起**；维度佐证 by_design 0.973（最稳）
#    vs scope_exceeds 0.757（明显更不稳）。
#    本 block 只做**一件事**：定义「预期范围」这个词，并禁掉三条实测摇摆的退路。
#    ★ 单独开关的理由：**改规则会同时动「稳定性」和「刻度」**⇒ 必须能单独 A/B（单变量原则）。
#
#  ★★★ 2026-10-13 20:1x **用户拍板：开启**（默认值由 "0" 改为 "1"）。
#      依据是  的 A/B 实测（两臂各 37 条 × 3 轮，同批样本）：
#        · 结论翻转率 **0.243 → 0.135**（近乎腰斩）
#        · 目标维度 scope_exceeds **0.757 → 0.865**
#        · by_design 0.973 → **1.000**
#        · ⚠️ 代价：多数票 vuln 计数 **26 → 30**、arg_source **0.622 → 0.514**
#      ⇒ 用户接受"尺子变严、洞变多"，换"结论更稳"。
#      ★ 想回到旧尺子：`AF_JUDGE_SCOPE2=0` 即可（单变量可逆）。
#      ★ 待办：`arg_source` 那一维被带坏了（0.514），**需要单独再收一次**。
SCOPE2_BLOCK = """

★★ 对上面 `scope_exceeds` 的补充定义（★ 按此执行，**不要自己重新权衡**）

「超出预期范围」只看一个东西：**工作目录约束**。
  问题不是"这个函数本来是干嘛的"，而是：
    这个实参的值，能不能被引导到**该模块自己声明的数据根之外**？
  · 能（路径可含 `..` / 可为绝对路径 / 可指向别处 / 无前缀约束）
      ⇒ **超出** ⇒ 若本函数内无校验，`scope_exceeds` = yes
  · 被数据结构**天然限制**在某个根内（例：从服务端自建的目录树字典里取出的相对名）
      ⇒ 未超出 ⇒ no

★★ 三条禁止（这三条正是实测摇摆的来源）：
 1. **不许用「这是设计功能」来判 `no`。** 设计功能也可能超出范围 ——
    那正是第四层存在的理由（`by_design=yes` 且 `scope_exceeds=yes` ⇒ vuln）。两维必须**独立作答**。
 2. **不许用「只读所以不算」来判 `no`。** 读任意文件与写任意文件是两种不同的危害，
    但**都超出"只处理自己目录下文件"的预期**；`os.listdir` / `open(..., "r")` 与 `open(..., "w")`
    在这一维上**同样算超出**。
 3. **不许用「没看到校验」以外的理由判 `unclear`。** `unclear` 只用于"依据在给定代码之外"；
    本函数内看完了就是看完了。
"""


# ★★ 可选规则补丁（开关 AF_JUDGE_ARGSRC=1，**默认开**）——  §二 /  §三之二
#    为什么加： 实测 —— 37 条里 9 条结论翻转，**9/9 由语义歧义引起**，
#    其中**有 4 条**是 `arg_source` 在 `tool_arg` ⇄ `llm_output` 之间跳（它是五个维度里最不稳的，0.622）。
#    开 SCOPE2 后它进一步掉到 **0.514**（成了最差的一维）⇒ **必须单独收一次**。
#    本 block 只做两件事：① 把五个取值的边界写死；② **给"看不出"一个明确去处（unknown）**。
#    ★ 单独开关的理由：它改的是「实参来源」这一维的约定，与 SCOPE2（范围这一维）**不是一回事**，
#      必须能分别 A/B / 分别回退（单变量原则）。
ARGSRC_BLOCK = """

★★ 对上面「第二层 · 实参来自哪」的补充定义（★ 按此执行，**不要自己重新权衡**）

`arg_source` 五个取值的**边界写死**：
  · `user_input` ← **只有明确来自人类直接输入**时才填：HTTP 请求体 / 表单 / query 参数、stdin、argv。
  · `llm_output` ← 来自 **LLM 的返回内容**（模型生成出来的东西）。
  · `tool_arg`   ← 来自**某个 Agent 工具的入参**（即 LLM 挑工具时传进去的那个参数）。
  · `constant` / `config` ← 写死的字面量 / 从配置文件读出来的。

★★ **一条禁止（这正是实测摇摆的来源）**：
  当数据流**只说到 `param`**、而你看不出它究竟是"工具入参"还是"人类输入"时
  ⇒ **一律填 `unknown`**。
  ★ 不许为了"看起来更具体"而在 user_input / llm_output / tool_arg 里挑一个 ——
     实测：9 条翻转里**有 4 条**是这一维在 `tool_arg` ⇄ `llm_output` 之间跳。
  ★ **`unknown` 是正确答案，不是失败。**
"""


def rubric_text() -> str:
    """实际使用的 rubric。★ 默认只有 `RUBRIC` 本体；开关按需追加 block。"""
    rt = RUBRIC
    # ★★ 默认 **"1" = 开启**（2026-10-13 用户批准"收 arg_source"）。回退：`AF_JUDGE_ARGSRC=0`。
    if os.environ.get("AF_JUDGE_ARGSRC", "1") == "1":
        rt += ARGSRC_BLOCK
    if os.environ.get("AF_JUDGE_OPARG", "0") == "1":
        rt += OPARG_BLOCK
    if os.environ.get("AF_JUDGE_REPOCFG", "0") == "1":
        rt += REPOCFG_BLOCK
    # ★★ 默认 **"1" = 开启**。
    #    要回到旧尺子：`AF_JUDGE_SCOPE2=0`（单变量、可逆）。
    if os.environ.get("AF_JUDGE_SCOPE2", "1") == "1":
        rt += SCOPE2_BLOCK
    return rt



def _build_user(fd: F.Finding, cache: dict) -> tuple[str, dict]:
    """组装这条 Finding 的上下文（带文件级缓存，避免重复读盘）。"""
    root = fd.src_root
    path = os.path.join(root, fd.sink_uri) if root else ""
    # ★ 缓存键必须带上 行号 + 守卫 + 数据流证据（都逐条不同），否则同文件会串
    _asrc = tuple((a.get("src_file"), a.get("src_line"))
                  for a in (getattr(fd, "arg_sources", None) or []))
    key = (path, fd.sink_line, tuple(fd.guards), _asrc)
    if key not in cache:
        qual, body = SC.enclosing_function(path, fd.sink_line) if path else ("", "")
        entry_body = SC.function_named(path, fd.entry) if (path and fd.entry) else ""
        # guard looks like "file.py:line:col" -> strip the column
        gl_nums = []
        for g in fd.guards:
            if "#" not in g:
                continue
            tail = g.split("#")[-1]                      # "1362:8"
            head = tail.split(":")[0]                    # "1362"
            if head.isdigit():
                gl_nums.append(int(head))
        guard_lines = SC.lines_at(path, gl_nums) if path else []
        # ★★ 实参来源所在函数的源码（开关 AF_JUDGE_ARGCTX，默认开）。
        #    为什么必须给：数据流会说"实参可追溯到 param `catalog` @ f.py:90"，
        #    而那个函数**不是 sink 所在函数** → 判定层看不到 → 只能说"依据在给定代码之外"。
        #    实测：14/14 条 needs_human 的理由全是这一句，
        #    而真正的校验（白名单/正则）恰恰常写在那函数体内。补上它才是"补输入"。
        arg_funcs = []
        if os.environ.get("AF_JUDGE_ARGCTX", "1") != "0" and root:
            seen: set = set()
            for a in (getattr(fd, "arg_sources", None) or []):
                if a.get("kind") == "local":     # 追不到源头 → 没有"来源函数"
                    continue
                sf = str(a.get("src_file") or "")
                sl = int(a.get("src_line") or 0)
                if not sf or not sl or (sf, sl) in seen:
                    continue
                seen.add((sf, sl))
                q, abody, _full = SC.function_by_basename(
                    root, sf, sl, prefer_dir=os.path.dirname(path))
                if abody:
                    arg_funcs.append({"file": sf, "line": sl, "qual": q, "body": abody})
        cache[key] = {"qual": qual, "body": body, "entry_body": entry_body,
                      "guard_lines": guard_lines, "arg_funcs": arg_funcs}
    c = cache[key]
    gl = "\n".join("  " + x for x in c["guard_lines"]) or "  （未能取到守卫行）"

    # ★ 跨过程数据流给出的「实参来源」（开关 dataflow-argsource）。
    #   目的：把"实参从哪来"从**要模型猜**变成**可引用的证据**。
    ds_lines = []
    for a in (getattr(fd, "arg_sources", None) or []):
        at = (a.get("arg_text") or "").replace("ControlFlowNode for ", "").strip()
        if a.get("kind") == "local":
            ds_lines.append(f"  实参 #{a.get('i')}（{at}）：跨过程分析**追不到任何源头**"
                            f"（既不是函数参数，也不是输入）")
        else:
            st = (a.get("src_text") or "").replace("ControlFlowNode for ", "").strip()
            ds_lines.append(f"  实参 #{a.get('i')}（{at}）：可追溯到 **{a.get('kind')}**"
                            f" → `{st}` @ {a.get('src_file')}:{a.get('src_line')}")
    ds_block = ("【静态数据流给出的实参来源（跨过程）】\n" + "\n".join(ds_lines) + "\n\n"
                if ds_lines else
                "【静态数据流给出的实参来源】\n  （本条没有数据流证据）\n\n")

    # ★ 实参来源所在函数的源码：这是"数据流说得出、但判定层看不到"的那一段。
    af_block = ""
    if c.get("arg_funcs"):
        chunks = []
        for x in c["arg_funcs"]:
            chunks.append(f"── `{x['file']}:{x['line']}` 所在的函数 `{x['qual']}`\n"
                          f"```python\n{x['body']}\n```")
        af_block = ("【实参来源所在函数的源码（★ 值在这里被接住）】\n"
                    + "\n".join(chunks) + "\n\n")

    # ★★ 配置来源证据
    #   为什么需要：`base_url = config.get("base_url")` 这类代码，判定层判不出
    #   "这是操作者自己配的，还是随仓库 clone 下来的" —— 两者可信度正好相反。
    #   ★ 这里**只贴证据原文**（哪一行在加载项目内配置 / 哪一行在做分层合并），
    #     **不替判定层下结论**；怎么判仍由 rubric 的尺度决定。
    cfg_block = ""
    if os.environ.get("AF_JUDGE_CFGSRC", "0") == "1" and root:
        try:
            ev = SC.config_source_evidence(root, os.path.join(root, fd.sink_uri))
        except Exception:
            ev = []
        if ev:
            rows = "\n".join(f"  {x['file']}:{x['line']}  [{x['why']}]  {x['text']}"
                             for x in ev)
            cfg_block = ("【配置来源证据（★ 原文，供你判断这个值受谁控制）】\n"
                         "  以下是本仓库里**与配置来源/分层**有关的真实代码行：\n"
                         f"{rows}\n"
                         "  ★ 提示：若出现「项目内配置文件」（如 .sampleproj.json / .mcp.json）"
                         "**在目标目录里被加载**、且它**能覆盖**别的层，\n"
                         "    那么运行者只是 clone/打开了这个仓库，**该文件由仓库作者控制**。\n\n")

    return (
        f"【项目】{fd.project}\n"
        f"【静态前端规则】{fd.rule}\n"
        f"【调用链】{fd.chain or '(无)'}\n"
        f"【入口函数名】{fd.entry or '(未知)'}\n\n"
        f"【危险调用点】{fd.sink_uri}:{fd.sink_line}\n"
        f"【该行源码】{fd.snippet}\n"
        f"【所在函数】{c['qual'] or '(未知)'}\n"
        f"```python\n{c['body'] or fd.snippet}\n```\n\n"
        + (f"【入口函数源码（同文件）】\n```python\n{c['entry_body']}\n```\n\n"
           if c["entry_body"] else "")
        + ds_block
        + af_block
        + cfg_block
        + f"【调用链上压着的 if 守卫（行号: 源码）】\n{gl}\n\n"
        "请判断：这个危险调用的实参是否可能来自不可信来源，守卫算不算真防护。"
    ), c


def judge_one(fd: F.Finding, cache: dict, tag: str = "kernel_judge") -> dict:
    """判一条。★ max_tokens 走「按需给额度」，见 MT_DEFAULT / MT_BIG 的说明。"""
    user, _ = _build_user(fd, cache)
    rt = rubric_text()
    env = os.environ.get("AF_JUDGE_MT", "")
    if env:                                   # 实验用：强制指定额度
        r = LC.ask_json(rt, user, tag=tag, max_tokens=int(env))
        r.pop("_raw", None)
        return r
    try:
        r = LC.ask_json(rt, user, tag=tag, max_tokens=MT_DEFAULT)
    except (ValueError, RuntimeError):
        # ★★ 必须同时捕 RuntimeError：`chat` 在 finish_reason=length 时抛的是
        #    `RuntimeError("LLM 调用失败（重试 N 次）…")`，**不是 ValueError** ——
        #    只捕 ValueError 的话升配路径永远走不到（踩过：验证时才撞出来）。
        # 走到这里 = MT_DEFAULT（内部还试过 2×）都拿不到合法 JSON，多半是输出被截断。
        # 升配重试一次；再失败就让它抛出去（上层记成 error，不许当成结论）。
        r = LC.ask_json(rt, user, tag=f"{tag}-big", max_tokens=MT_BIG)
    r.pop("_raw", None)
    return r


def judge(findings: list[F.Finding], on_log=print, tag: str = "kernel_judge",
          votes: int = 1) -> None:
    """就地给每条 Finding 填 ai_* 字段。

    ★★ votes > 1：同一条**重复判 N 次再聚合**。
       为什么需要：实测同一条 finding 在温度 0 下重复判 5 次，**8 条里 4 条结论会翻**
       。所以单次跑的 vuln 计数**不可复现**。
       ★ 聚合策略**不是实现细节，它直接决定报什么**：
         · 多数票 → 保守（会丢掉那些"少数票才算 vuln"的真阳）
         · 任一票 → 激进（假阳性也进来）
         这里默认用**多数票**；平票时取 `needs_human`（保守方向）。
       ★ 成本 ×N。而且每次 vote 必须用**不同的 tag**，否则命中缓存 → N 次返回同一个结果、
         聚合毫无意义（这是这个功能最容易踩的坑）。
    """
    cache: dict = {}
    for i, fd in enumerate(findings, 1):
        try:
            if votes <= 1:
                r = judge_one(fd, cache, tag=tag)
                _apply(fd, r)
            else:
                reps = []
                for k in range(votes):
                    reps.append(judge_one(fd, cache, tag=f"{tag}-v{k}"))
                r = _aggregate(reps)
                _apply(fd, r)
                fd.judge_json["_votes"] = [x.get("ai_verdict") for x in reps]
        except Exception as e:
            fd.ai_verdict = "error"
            fd.ai_reason = f"{type(e).__name__}: {e}"[:200]
            on_log(f"  [{i}/{len(findings)}] ★ LLM 失败 {fd.sink_uri}:{fd.sink_line} — {e}")
            continue
        on_log(f"  [{i}/{len(findings)}] {fd.ai_verdict:11} conf={fd.ai_confidence:.2f} "
               f"byd={fd.by_design:7} exc={fd.scope_exceeds:7} "
               f"{fd.sink_uri.split('/')[-1]}:{fd.sink_line}  {fd.ai_reason[:52]}")


def _apply(fd: F.Finding, r: dict) -> None:
    fd.ai_verdict = str(r.get("ai_verdict", "?"))
    fd.ai_confidence = float(r.get("confidence") or 0.0)
    fd.by_design = str(r.get("by_design", "?"))
    fd.scope_exceeds = str(r.get("scope_exceeds", "?"))
    fd.arg_source = str(r.get("arg_source", "?"))
    fd.guards_real = str(r.get("guards_real", "?"))
    fd.ai_reason = str(r.get("one_line", ""))[:200]
    fd.judge_json = r


def _aggregate(reps: list[dict]) -> dict:
    """N 次判定的聚合。★ 策略写在这里，且必须能被报告引用（meta.judge_aggregation）。"""
    from collections import Counter
    vd = [str(x.get("ai_verdict", "?")) for x in reps]
    c = Counter(vd)
    top = c.most_common()
    if len(top) > 1 and top[0][1] == top[1][1]:
        verdict = "needs_human"            # ★ 平票 → 保守
    else:
        verdict = top[0][0]
    # 其余字段：取"结论与多数票一致"的第一次运行的值，保证字段之间不自相矛盾
    base = next((x for x in reps if str(x.get("ai_verdict")) == verdict), reps[0])
    out = dict(base)
    out["ai_verdict"] = verdict
    out["confidence"] = round(sum(float(x.get("confidence") or 0) for x in reps) / len(reps), 3)
    out["one_line"] = f"[{len(reps)}次多数票 {vd.count(verdict)}/{len(reps)}] " + str(base.get("one_line", ""))
    return out


def cost_report() -> str:
    return LC.USAGE.report()
