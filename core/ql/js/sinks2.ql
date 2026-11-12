/**
 * @name window-level sink (receiver-aware)
 * @description window 级 + 一条不追数据的启发式：接收者名字像正则的 exec 不算。
 *              与 sinks.ql 的差别只有一句「多看一眼接收者叫什么」，不追定义、不追类型。
 * @kind problem
 * @id js-window/sink2
 * @problem.severity warning
 */

import javascript

predicate looksLikeRegex(Expr e) {
  e instanceof RegExpLiteral
  or exists(string n | n = e.(VarRef).getName() |
       n.regexpMatch("(?i).*(pattern|regex|regexp|re)$"))
  // ★★ 补：只看名字不够。`TYPED_ID.exec(task.content_id)` 的接收者
  //    叫 TYPED_ID —— 名字不像 regex，但它在文件内被赋成了正则字面量。
  //    这条不加，openbiliclaw 会多报一条纯误报（实测就是这条）。
  //    仍然是**文件内**的判断（只看赋值，不跨函数），所以还算 window 档。
  or exists(VarRef v | v = e | v.getVariable().getAnAssignedExpr() instanceof RegExpLiteral)
}

from CallExpr c
where
  c.getCalleeName() in ["eval", "Function", "exec", "execSync", "spawn", "spawnSync", "execFile"]
  and not (
    c.getCalleeName() = "exec"
    and exists(Expr r | r = c.(MethodCallExpr).getReceiver() | looksLikeRegex(r))
  )
select c, "sink:" + c.getCalleeName()
