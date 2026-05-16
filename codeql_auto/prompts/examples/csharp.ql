/**
 * @name Reflected XSS via Response.Write
 * @description Detects HttpResponse.Write calls whose argument is tainted
 *              by HTTP request data without encoding.
 * @kind path-problem
 * @problem.severity error
 * @id cs/reflected-xss-response-write
 * @tags security
 *       external/cwe/cwe-079
 */

import csharp
import semmle.code.csharp.security.dataflow.XSSQuery
import XSS::PathGraph

from XSS::PathNode source, XSS::PathNode sink
where XSS::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability due to $@.", source.getNode(), "user-provided value"
