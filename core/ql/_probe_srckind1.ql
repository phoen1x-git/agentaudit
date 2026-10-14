/**
 * @name af srcKind(MaD) probe (P2a)
 * @kind problem
 * @problem.severity warning
 * @id af/srckind-mad1
 * @description 探针：我们的 srcKind 到底有没有吃到 MaD 的 source。
 */
import python
import argsource_cfg
import semmle.python.dataflow.new.DataFlow

from DataFlow::Node n, string k
where srcKind(n, k) and k = "llm-output"
select n, "SRCKIND-OK kind=" + k + " @ " + n.toString()
       + " @ " + n.getLocation().toString()
