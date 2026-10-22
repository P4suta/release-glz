include "required";

def modes:
  [false, "false", "skipped"],
  [false, "true", "success"],
  [true, "false", "success"],
  [true, "true", "success"];

def result: "success", "failure", "cancelled", "skipped";

def cases:
  modes as $mode | result as $changes | result as $checks |
  {
    full: $mode[0],
    needs: {
      changes: {result: $changes, outputs: {runtime: $mode[1]}},
      checks: {result: $checks}
    },
    expected: ($changes == "success" and $checks == $mode[2])
  };

def actual: . as $case | .needs | required($case.full);

def report(verdict):
  reduce cases as $case ({total: 0, matched: 0, admitted: 0};
    ($case | verdict) as $actual |
    .total += 1 |
    .matched += (if $actual == $case.expected then 1 else 0 end) |
    .admitted += (if $actual == true then 1 else 0 end));

def invalid:
  null, 0, "invalid", [],
  (.full = null), (.full = "false"), (.full = 1),
  (del(.needs.changes.outputs)),
  (["changes", "checks"][] as $job |
    del(.needs[$job]), (.needs[$job] = null),
    (.needs[$job].result = null), (.needs[$job].result = "unknown")),
  (del(.needs.changes.outputs.runtime)),
  ([null, true, false, 0, 1, "", "TRUE", [], {}][] as $value |
    .needs.changes.outputs.runtime = $value);

report(actual) as $production |
report(true) as $approve_all |
report(false) as $reject_all |
report(.needs | all(.[]; .result == "success" or .result == "skipped")) as $allow_skips |
{
  full: false,
  needs: {
    changes: {result: "success", outputs: {runtime: "true"}},
    checks: {result: "success"}
  }
} |
[invalid | (try actual catch false) == false] as $invalid |
if $production == {total: 64, matched: 64, admitted: 4} and
   $approve_all.matched < $production.total and
   $reject_all.matched < $production.total and
   $allow_skips.matched < $production.total and
   ($invalid | length) == 26 and ($invalid | all)
then {cases: $production.total, invalid: ($invalid | length), rejecting_controls: 3}
else error("required-job contract failed")
end
