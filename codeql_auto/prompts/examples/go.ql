/**
 * @name SSRF via http.Get with user-controlled URL
 * @description Detects calls to net/http.Get / http.Client.Get whose URL
 *              argument is tainted by an incoming HTTP request.
 * @kind path-problem
 * @problem.severity error
 * @id go/ssrf-http-get
 * @tags security
 *       external/cwe/cwe-918
 */

import go
import semmle.go.dataflow.TaintTracking
import semmle.go.security.RequestForgeryQuery
import RequestForgeryFlow::PathGraph

from RequestForgeryFlow::PathNode source, RequestForgeryFlow::PathNode sink
where RequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "The URL of this request depends on a $@.", source.getNode(), "user-provided value"
