def required($full):
  ($full | type) == "boolean" and
  .changes.result == "success" and
  (.changes.outputs.runtime == "true" or .changes.outputs.runtime == "false") and
  .checks.result == (if $full or .changes.outputs.runtime == "true" then "success" else "skipped" end);
