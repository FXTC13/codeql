/**
 * @name Command injection via Kernel#system or backticks
 * @description Detects calls to system/exec/`` with arguments tainted by
 *              params/request data.
 * @kind path-problem
 * @problem.severity error
 * @id rb/command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import ruby
import codeql.ruby.security.CommandInjectionQuery
import CommandInjectionFlow::PathGraph

from CommandInjectionFlow::PathNode source, CommandInjectionFlow::PathNode sink
where CommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This command depends on $@.", source.getNode(), "a user-provided value"
