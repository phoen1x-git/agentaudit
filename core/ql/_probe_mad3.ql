/**
 * @name af MaD probe (P2a)
 * @kind problem
 * @problem.severity warning
 * @id af/mad-probe3
 * @description 探针：MaD 的 sourceModel 到底有没有被本 db 读到。
 */
import python
import semmle.python.ApiGraphs
import semmle.python.frameworks.data.ModelsAsData

from API::Node n, string k
where n = ModelOutput::getASourceNode(k) and k = "llm-output"
select n, k + " @ " + n.toString()
