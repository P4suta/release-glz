include "required";

def result: "success", "failure", "cancelled", "skipped";

def cases:
  result as $checks |
  {
    needs: {checks: {result: $checks}},
    expected: ($checks == "success")
  };

def actual: .needs | required;

def report(verdict):
  reduce cases as $case ({total: 0, matched: 0, admitted: 0};
    ($case | verdict) as $actual |
    .total += 1 |
    .matched += (if $actual == $case.expected then 1 else 0 end) |
    .admitted += (if $actual == true then 1 else 0 end));

def invalid:
  null, 0, "invalid", [],
  del(.needs.checks), (.needs.checks = null),
  (.needs.checks.result = null), (.needs.checks.result = "unknown");

report(actual) as $production |
report(true) as $approve_all |
report(false) as $reject_all |
report(.needs | all(.[]; .result == "success" or .result == "skipped")) as $allow_skips |
{needs: {checks: {result: "success"}}} |
[invalid | (try actual catch false) == false] as $invalid |
if $production == {total: 4, matched: 4, admitted: 1} and
   $approve_all.matched < $production.total and
   $reject_all.matched < $production.total and
   $allow_skips.matched < $production.total and
   ($invalid | length) == 8 and ($invalid | all)
then {cases: $production.total, invalid: ($invalid | length), rejecting_controls: 3}
else error("required-job contract failed")
end
