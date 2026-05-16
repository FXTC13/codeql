/**
 * @name SQL injection via Statement.execute
 * @description Detects java.sql.Statement.execute(String) calls whose argument
 *              is tainted by an HttpServletRequest parameter.
 * @kind path-problem
 * @problem.severity error
 * @id java/sql-injection-statement
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL query depends on a $@.", source.getNode(), "user-provided value"
