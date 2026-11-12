/**
 * @name window-level sink (no heuristic)
 * @description 只报 sink 位置与所在函数，不追来源、不追调用链 —— 纯 window 级。
 *              留着它是因为「加了启发式之后少报了几条」这句话必须能对得上账：
 *              两版跑同一靶，差集就是启发式吃掉的那些，逐条可看。
 * @kind problem
 * @id js-window/sink
 * @problem.severity warning
 */

import javascript

from CallExpr c
where
  c.getCalleeName() in ["eval", "Function", "exec", "execSync", "spawn", "spawnSync", "execFile"]
select c, "sink:" + c.getCalleeName()
