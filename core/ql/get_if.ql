/**
 * @id py-qs/bb-l7
 * @severity warning
 * @precision low
 * @description reachable guards on the path from a function entry to a sink call
 * @kind problem
 */

// 抛出去的是「这个 sink 之前经过哪些 if」。
//
// 原来的做法是自己拿 BasicBlock 拼图：TestBlock 认 if 的条件块、
// edges/icfg_edge 手工把 call site 的块连到 callee 的块，再从 sink 所在块反向走。
// 现在只用库自带的 BasicBlock.getASuccessor*()，不自己造边。
//
// ★ 跨函数那一层**故意不保留**。原版靠 icfg_edge 把调用链上游的 if 也算进守卫，
//   实测 panwatch 上那条是 `lifespan` 里 `if init_auth_from_env(db):`
//   —— 它判断的是"要不要从环境变量初始化认证账号"，和 sink（`subprocess.run`
//   装 playwright）没有任何关系。上游函数里"任意一个 if"被当成这个 sink 的守卫，
//   是误报，不是能力。
//
// ★ 输出从拼接字符串改成了 JSON，格式由 call.qll 的 locJson 统一定义。

import call.call
import util.util

/** if 语句 i 的条件块，能在 CFG 上走到 sink 所在的块。 */
predicate reachesBefore(If i, CallNode sink) {
  i.getScope() = sink.getScope() and
  i.getTest().getAFlowNode().getBasicBlock().getASuccessor*().contains(sink)
}

from CallNode sink, Source source
where
  sink = source.getCallee() and
  isIncludeLocation2(sink.getScope().getLocation())
select sink,
  source.getJson("py-qs/bb-l7",
    "[" + concat(If i, Location loc |
      reachesBefore(i, sink) and loc = i.getTest().getLocation()
    |
      locJson(i.getScope().(Function).getQualifiedName(), loc), ",") + "]",
    "[]")
