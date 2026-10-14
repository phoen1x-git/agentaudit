/**
 * @name py-qs/arg-source
 * @id py-qs/arg-source
 * @kind problem
 * @severity warning
 * @precision low
 * @description 对每个 sink 调用点的**每个实参**，用跨过程污点分析给出"它从哪来"。
 *
 * ★★ 这条查询填的是论文自己的缺口：
 *    论文 66 份 SARIF 里 `codeFlows` 全为 0 —— 它的"污点"只是 `localTaint`（函数内），
 *    从没跨过程追过。
 * ★ 它修的是**判定层的不稳**（docs/108）：判定层被问"实参从哪来"，但静态前端从没给它这个数据，
 *    于是它在「诚实写 unknown」和「猜一个」之间横跳（arg_source 稳定率仅 0.25）。
 *
 * 输出（@kind problem，2 列；细节用 `@@` 分隔编进 message，前端再拆）：
 *   (sink 位置,  "kind@@argIndex@@argLine@@argText@@srcFile@@srcLine@@srcText")
 *   来源种类 kind ∈ { llm-client | web-request | stdin | argv | param | local }
 *     llm-client  可追溯到一次 LLM 客户端调用（配置见 core/config/sources.yml）
 *     web-request 可追溯到 Web 请求对象（request.args/json/...）
 *     stdin/argv  可追溯到 input() / sys.argv
 *     param       追到**函数参数**就断了（真正来源在本函数之外 → 需要看调用方）
 *     local       追不到任何源头（大概率是局部量/常量）
 *
 * ★ 为什么是 2 列：`@kind problem` 要求**偶数列**（entity + message 成对），
 *   9 列会报 "must select an even number of columns"（踩过）。
 *   同样地，`scan.log` 那种多字段结果不能直接 select —— 编进 message 再拆。
 */
import python
import call.call
import argsource_cfg
import semmle.python.dataflow.new.DataFlow

from CallNode c, int i, DataFlow::Node arg, string kind,
     string sfile, int sline, string stext, int aline, string atext
where
  is_sink(c) and
  arg.asCfgNode() = c.getArg(i) and
  aline = c.getArg(i).getLocation().getStartLine() and
  atext = c.getArg(i).toString() and
  (
    exists(DataFlow::Node s |
      ArgFlow::flow(s, arg) and
      srcKind(s, kind) and
      sfile = s.getLocation().getFile().getBaseName() and
      sline = s.getLocation().getStartLine() and
      stext = s.toString()
    )
    or
    (
      kind = "local" and
      not ArgFlow::flowTo(arg) and
      sfile = "" and sline = 0 and stext = ""
    )
    or
    (
      // ★ 数据流说有来源，但来源**不是我们认得的种类**（框架内部/未建模的汇总节点）。
      //   不留这一档的话这些实参会**一行都没有** —— 静默丢数据比报"不知道"更糟（踩过）。
      kind = "opaque" and
      ArgFlow::flowTo(arg) and
      not exists(DataFlow::Node s | ArgFlow::flow(s, arg) and srcKind(s, _)) and
      sfile = "" and sline = 0 and stext = ""
    )
  )
select c, kind + "@@" + i.toString() + "@@" + aline.toString() + "@@" + atext
       + "@@" + sfile + "@@" + sline.toString() + "@@" + stext
