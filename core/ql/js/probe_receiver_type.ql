/**
 * @name receiver type probe (four attempts, one query)
 * @description 量 window 档的假阳：想知道 `xxx.exec()` 的接收者到底是不是 child_process。
 *              这是第六步试过四版（ty.ql~ty4.ql）之后留下的那一版 —— **四版都空**：
 *              CodeQL JS 在这批调用上 `getReceiver().getType()` 求值为空类型，
 *              `MethodCallExpr.getMethodName()` 也一样。结论不是"没类型"，是
 *              **这一档拿不到类型**，所以 JS 只能停在 window，升 full 得换路子。
 * @kind problem
 * @id js-window/probe-receiver-type
 * @problem.severity recommendation
 */

import javascript

from MethodCallExpr c
where c.getMethodName() = "exec"
select c,
       "recv=" + c.getReceiver().toString(),
       "type=" + c.getReceiver().getType().toString(),
       "typeName=" + c.getReceiver().getType().getName()
