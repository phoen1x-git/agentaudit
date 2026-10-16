// ★ 由 core/gen_ql.py 生成，不要手改。
// ★ 本文件 import 了 dataflow 库 → 这里的 `CallNode` 不是 AST 那个，
//   所以**不要在这里写任何 AST 类型**（都在 argsource_ast.qll 里）。详见 gen_ql.py。
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import argsource_ast

/** 源头种类：AST 层能认的（见 argsource_ast.qll）+ 函数参数这一档。 */
predicate srcKind(DataFlow::Node n, string k) {
  srcKindCfg(n.asCfgNode(), k)
  or
  (n instanceof DataFlow::ParameterNode and k = "param")
  // ★ 跨过程分析里，参数常常表现为**汇总节点**（toString 形如 "[summary param] position 1 in f"），
  //   它们不是 ParameterNode。不认它们会**静默丢行**（踩过：sample-toolkit exec 的 arg0 消失了）。
  or
  (n.toString().matches("[summary param]%") and k = "param")
}

module ArgSourceCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { srcKind(n, _) }
  predicate isSink(DataFlow::Node n) { isSinkArgCfg(n.asCfgNode()) }
}

module ArgFlow = TaintTracking::Global<ArgSourceCfg>;
