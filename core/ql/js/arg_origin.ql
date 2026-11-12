/**
 * @name sink argument origin (window-level)
 * @description 对每个危险调用的每个实参，标出它是不是字面量、原文长什么样。
 *              这是 window 档能给出的最诚实的答案：**只看这一行**，不跨函数、
 *              不追变量定义。要追定义是 full 档的事，本查询有意不做。
 *              ★ 模板字面量单列成 `template`：它可能含 `${...}` 插值，
 *                但 QL 侧判断插值不稳（第一版 `ArrayLiteral` 这类类型名还写错过），
 *                所以把文本交给 Python 侧看有没有 `${`，不在这里猜。
 * @kind problem
 * @id js-window/arg-origin
 * @problem.severity warning
 */

import javascript

/** 纯字面量：字符串、数字、布尔、null、正则。 */
predicate plainLiteral(Expr e) {
  e instanceof StringLiteral
  or e instanceof NumberLiteral
  or e instanceof BooleanLiteral
  or e instanceof NullLiteral
  or e instanceof RegExpLiteral
}

/** ★ 和 sinks2.ql 用同一套排除：接收者名字像正则的 `.exec()` 不算危险调用。
 *  不加这条，cascadeflow 这一轮会从 1 条涨到 8+ 条，多出来的全是 `pattern.exec(s)`。 */
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

predicate isSinkCall(CallExpr c) {
  c.getCalleeName() in ["eval", "Function", "exec", "execSync", "spawn", "spawnSync", "execFile"]
  and not (
    c.getCalleeName() = "exec"
    and exists(Expr r | r = c.(MethodCallExpr).getReceiver() | looksLikeRegex(r))
  )
}

from CallExpr c, int i, Expr a, string kind
where
  isSinkCall(c)
  and a = c.getArgument(i)
  and (
    plainLiteral(a) and kind = "literal"
    or
    a instanceof TemplateLiteral and kind = "template"
    or
    a instanceof VarRef and kind = "varref"
    or
    not plainLiteral(a)
    and not a instanceof TemplateLiteral
    and not a instanceof VarRef
    and kind = "expr"
  )
// ★ message 每行都带上 sink 名（`spawnSync|arg0:varref:command`）：
//   不带的话 Python 侧不知道这是哪个 sink，就没法判「哪几个实参是危险位置」，
//   于是 options 对象也被算成"非字面量"，全部候选都变成 has_expr（实测 11/11 全是）。
select c, c.getCalleeName() + "|arg" + i.toString() + ":" + kind + ":" + a.toString()
