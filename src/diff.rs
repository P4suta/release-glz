/// Render a deterministic, valid unified diff.
///
/// v1 intentionally emits one complete hunk. Configuration and managed
/// workflow files are small, and a complete hunk avoids platform-specific
/// dependencies while remaining consumable by standard patch tooling.
pub fn unified_diff(path: &str, current: &str, rendered: &str) -> String {
    if current == rendered {
        return String::new();
    }

    let path = path.replace(['\r', '\n'], "?");
    let old_count = current.lines().count();
    let new_count = rendered.lines().count();
    let old_path = if current.is_empty() {
        "/dev/null"
    } else {
        &path
    };
    let new_path = if rendered.is_empty() {
        "/dev/null"
    } else {
        &path
    };
    let mut output = format!(
        "--- {old_path}\n+++ {new_path}\n@@ -{} +{} @@\n",
        hunk_range(old_count),
        hunk_range(new_count)
    );
    push_lines(&mut output, '-', current);
    push_lines(&mut output, '+', rendered);
    output
}

fn hunk_range(count: usize) -> String {
    match count {
        0 => "0,0".into(),
        1 => "1".into(),
        _ => format!("1,{count}"),
    }
}

fn push_lines(output: &mut String, prefix: char, contents: &str) {
    if contents.is_empty() {
        return;
    }
    for line in contents.lines() {
        output.push(prefix);
        output.push_str(line);
        output.push('\n');
    }
    if !contents.ends_with('\n') {
        output.push_str("\\ No newline at end of file\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_diff_has_patch_headers_hunk_ranges_and_no_newline_markers() {
        let diff = unified_diff("gleam.toml", "name = \"old\"", "name = \"new\"\n");
        assert!(diff.starts_with("--- gleam.toml\n+++ gleam.toml\n@@ -1 +1 @@\n"));
        assert!(diff.contains("-name = \"old\"\n\\ No newline at end of file\n"));
        assert!(diff.ends_with("+name = \"new\"\n"));
    }

    #[test]
    fn unchanged_input_has_no_diff() {
        assert!(unified_diff("gleam.toml", "same\n", "same\n").is_empty());
    }

    #[test]
    fn new_files_use_the_standard_null_source_header() {
        let diff = unified_diff("generated.yml", "", "name: generated\n");
        assert!(diff.starts_with("--- /dev/null\n+++ generated.yml\n@@ -0,0 +1 @@\n"));
    }
}
