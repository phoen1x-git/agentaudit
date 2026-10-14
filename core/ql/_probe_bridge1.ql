/**
 * @name af MaD bridge probe (P2a)
 * @kind problem
 * @problem.severity warning
 * @id af/mad-bridge1
 * @description 探针：ModelOutput::getASourceNode(k).asSource() 到底能不能产出 DataFlow::Node。
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.frameworks.data.ModelsAsData

from DataFlow::Node d
where d = ModelOutput::getASourceNode("llm-output").asSource()
select d, "BRIDGE-OK @ " + d.toString() + " @ " + d.getLocation().toString()
