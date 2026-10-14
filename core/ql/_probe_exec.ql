/** @id probe/exec-nodes @kind problem @problem.severity info */
import python

from AstNode n
where n.getLocation().getFile().getRelativePath().matches("%code_env.py%")
  and n.getLocation().getStartLine() = 41
select n, n.getAQlClass(), n.toString()
