// ★ 由 core/gen_ql.py 从 core/config/sources.yml 生成，不要手改。
// ★★ 本文件**故意不 import dataflow 库** —— 一旦 import，`CallNode` 会被解析成
//    dataflow 的类，下面所有 AST 用法都会报"cannot be resolved"。详见 gen_ql.py。
import python
import call.call

/** sink 调用的实参节点（AST 层）。★ `CallNode.getArg(i)` 返回的就是 ControlFlowNode。 */
predicate isSinkArgCfg(ControlFlowNode cn) {
  exists(CallNode c, int i |
    is_sink(c) and
    cn = c.getArg(i)
  )
}

/**
 * 实参节点的「来源种类」（AST 层）。
 * 同一节点可能匹配多条 → 由查询层按优先级取。
 * （`param` 那一档在 argsource_cfg.qll 里，因为要用 dataflow 的 ParameterNode。）
 */
predicate srcKindCfg(ControlFlowNode cn, string k) {
  exists(CallNode c, string nm |
    cn = c and
    c.getFunction().(AttrNode).getNode().getName() = nm and
    nm in ["chat", "invoke", "generate", "completion", "complete", "predict", "ask"] and
    k = "llm-client")
  or
  exists(Attribute a, string nm |
    cn = a.getAFlowNode() and
    a.getObject().toString().regexpMatch(".*request") and
    a.getName() = nm and
    nm in ["args", "json", "form", "values", "data", "files", "headers", "cookies"] and
    k = "web-request")
  or
  exists(CallNode c, string nm |
    cn = c and
    c.getFunction().(NameNode).getNode().toString() = nm and
    nm in ["input"] and
    k = "stdin")
  or
  exists(Attribute a, string nm |
    cn = a.getAFlowNode() and
    a.getObject().toString().regexpMatch(".*sys") and
    a.getName() = nm and
    nm in ["argv"] and
    k = "argv")
}
