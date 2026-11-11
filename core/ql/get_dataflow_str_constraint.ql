/**
 * @id py-qs/str-constraint
 * @severity warning
 * @precision low
 * @description argument shaped by string operations before it reaches the sink
 * @kind problem
 */

// 判的是「这个实参是不是某个字符串函数的产物」。
//
// 第一版想纯用语法树（实参子树里找 split/format/join）来避开数据流引擎，
// 实测在真实靶上一条都报不出来：真实代码里字符串加工总是先赋给变量，
// 再经过列表推导、解包、f-string 好几步才到 sink，子树里根本看不到那个调用。
// 所以这一层必须走数据流；能改的是**用哪条边**，不是要不要用。
//
// 用的是 DataFlow::localFlowStep*（本函数内的数据流传递闭包），不是
// TaintTracking::localTaint：这里问的是"这个值从哪来"，不是"污点传没传到"，
// 污点规则会把无关的容器传递也算进来。问题窄了，谓词也就窄了。

import call.call
import util.util
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/** 会改变字符串形状的调用，按方法名认。 */
string strShapingOp() {
  result = ["split", "index", "rindex", "format", "join", "replace",
            "strip", "lstrip", "rstrip", "encode", "decode"]
}

/** 一个调用节点，其被调方法是上面集合里的某一个。 */
class StrOpCall extends CallNode {
  StrOpCall() { this.getFunction().(AttrNode).getName() = strShapingOp() }
}

/** sink 的第 i 个实参，它的值在本函数内可以追到调用 cn。
 *
 *  ★ 这一步必须用污点边，不能用普通数据流边：真实代码里
 *    `url = f"...{namespace}..."` 这种格式化在普通数据流里是断的，
 *    而 taint step 会穿过去。实测用 DataFlow::localFlowStep* 时
 *    真实靶上一条都报不出来（0/5），换回污点边才恢复。
 */
predicate argComesFrom(CallNode sink, CallNode cn, int i) {
  exists(DataFlow::CallCfgNode sinkNode, DataFlow::CallCfgNode srcNode |
    sinkNode.asCfgNode() = sink and
    srcNode.asCfgNode() = cn and
    TaintTracking::localTaint(srcNode, sinkNode.getArg(i))
  )
}

/** 函数体里把某个调用的结果存进变量、再把该变量 return 出来 —— 取那个调用。 */
CallNode returnedCall(Function f) {
  exists(AssignStmt a, Return r, CallNode cn, NameNode n |
    a.getScope() = f and
    r.getScope() = f and
    a.getATarget().getAFlowNode() = n and
    a.getValue().getAFlowNode() = cn and
    r.getValue().getAFlowNode().(NameNode).getId() = n.getId()
  |
    result = cn
  )
}

/** 真正起约束作用的那个调用：要么它就是字符串加工，要么它绕了一层 return 拿到加工结果。 */
CallNode constraintOf(CallNode sink) {
  exists(CallNode cn, int i |
    argComesFrom(sink, cn, i) and
    (
      result = cn and cn instanceof StrOpCall
      or
      not cn instanceof StrOpCall and
      result = returnedCall(cn.getScope().(Function))
    )
  )
}

from Source s
where exists(constraintOf(s.getCallee()))
select s.getCallee(),
  s.getJson("py-qs/str-constraint", "[]", "[" + concat(CallNode cn |
      cn = constraintOf(s.getCallee())
    |
      locJson(print_function(cn), cn.getLocation()), ",") + "]")
