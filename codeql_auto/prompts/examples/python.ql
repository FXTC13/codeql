/**
 * @name Command injection via subprocess with shell=True
 * @description Detects subprocess.run / subprocess.call invocations where shell=True
 *              and an argument is tainted by HTTP request data.
 * @kind path-problem
 * @problem.severity error
 * @id py/command-injection-subprocess
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.security.dataflow.CommandInjectionQuery
import semmle.python.security.dataflow.CommandInjectionCustomizations::CommandInjection
import CommandInjectionFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This command depends on $@.", source.getNode(), "a user-provided value"
