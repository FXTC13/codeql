/**
 * @name Format string vulnerability in printf-family functions
 * @description Detects printf/fprintf/sprintf/snprintf calls where the format
 *              argument is not a string literal and may be attacker-controlled.
 * @kind problem
 * @problem.severity error
 * @id cpp/format-string-injection
 * @tags security
 *       external/cwe/cwe-134
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources

class PrintfLikeCall extends FunctionCall {
  int formatArgIndex;

  PrintfLikeCall() {
    exists(string name | name = this.getTarget().getName() |
      name = "printf" and formatArgIndex = 0
      or
      (name = "fprintf" or name = "sprintf") and formatArgIndex = 1
      or
      (name = "snprintf" or name = "fnprintf") and formatArgIndex = 2
    )
  }

  Expr getFormatArg() { result = this.getArgument(formatArgIndex) }
}

module FormatStringConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(PrintfLikeCall call | sink.asExpr() = call.getFormatArg())
  }
}

module FormatStringFlow = TaintTracking::Global<FormatStringConfig>;

from PrintfLikeCall call, DataFlow::Node source, DataFlow::Node sink
where
  sink.asExpr() = call.getFormatArg() and
  FormatStringFlow::flow(source, sink) and
  not call.getFormatArg() instanceof Literal
select call, "Format string in $@ is tainted by $@.",
  call.getTarget(), call.getTarget().getName(),
  source, "this source"
