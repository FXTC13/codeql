/**
 * @name Insecure WebView load with tainted HTML
 * @description Detects WKWebView.loadHTMLString / UIWebView.loadHTMLString calls
 *              where the HTML payload is tainted by user-controlled input.
 * @kind path-problem
 * @problem.severity error
 * @id swift/insecure-webview-load
 * @tags security
 *       external/cwe/cwe-079
 */

import swift
import codeql.swift.dataflow.DataFlow
import codeql.swift.dataflow.TaintTracking
import codeql.swift.security.SensitiveExprs
import codeql.swift.dataflow.FlowSources

class WebViewLoadSink extends DataFlow::Node {
  WebViewLoadSink() {
    exists(CallExpr c |
      c.getStaticTarget().getName().matches("loadHTMLString%") and
      this.asExpr() = c.getArgument(0).getExpr()
    )
  }
}

module WebViewConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof WebViewLoadSink }
}

module WebViewFlow = TaintTracking::Global<WebViewConfig>;
import WebViewFlow::PathGraph

from WebViewFlow::PathNode source, WebViewFlow::PathNode sink
where WebViewFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "WebView loads HTML containing $@.", source.getNode(), "user-provided data"
