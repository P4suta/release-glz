use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::model::{ApiChange, ApiChangeKind, ApiDiff, ApiStatus, Bump};

#[derive(Debug, Clone, Default)]
struct ModuleSurface {
    functions: BTreeMap<String, String>,
    constants: BTreeMap<String, String>,
    aliases: BTreeMap<String, String>,
    types: BTreeMap<String, TypeSurface>,
}

#[derive(Debug, Clone, Default)]
struct TypeSurface {
    signature: String,
    constructors: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct Surface {
    modules: BTreeMap<String, ModuleSurface>,
}

/// Compare two Gleam `package-interface.json` documents.
///
/// Documentation, deprecation text, and unlabeled argument names are absent
/// from signatures. Type variable ids are canonicalized by first occurrence,
/// making compiler-generated alpha-renames equivalent.
pub fn compare(old: &[u8], new: &[u8]) -> Result<ApiDiff> {
    let old = parse_surface(old).context("invalid baseline package interface")?;
    let new = parse_surface(new).context("invalid local package interface")?;
    let mut changes = Vec::new();

    let old_modules: BTreeSet<_> = old.modules.keys().cloned().collect();
    let new_modules: BTreeSet<_> = new.modules.keys().cloned().collect();
    for module in old_modules.difference(&new_modules) {
        changes.push(change(
            ApiChangeKind::Removed,
            format!("module {module}"),
            true,
            format!("removed public module `{module}`"),
        ));
    }
    for module in new_modules.difference(&old_modules) {
        changes.push(change(
            ApiChangeKind::Added,
            format!("module {module}"),
            false,
            format!("added public module `{module}`"),
        ));
    }
    for module in old_modules.intersection(&new_modules) {
        compare_module(
            module,
            &old.modules[module],
            &new.modules[module],
            &mut changes,
        );
    }

    changes.sort_by(|a, b| a.path.cmp(&b.path).then(a.summary.cmp(&b.summary)));
    let impact = if changes.iter().any(|change| change.breaking) {
        Bump::Major
    } else if changes.is_empty() {
        Bump::None
    } else {
        Bump::Minor
    };
    Ok(ApiDiff {
        status: if changes.is_empty() {
            ApiStatus::Compatible
        } else {
            ApiStatus::Changed
        },
        impact,
        changes,
    })
}

fn compare_module(
    module: &str,
    old: &ModuleSurface,
    new: &ModuleSurface,
    changes: &mut Vec<ApiChange>,
) {
    compare_items(module, "function", &old.functions, &new.functions, changes);
    compare_items(module, "constant", &old.constants, &new.constants, changes);
    compare_items(module, "type alias", &old.aliases, &new.aliases, changes);

    let old_types: BTreeSet<_> = old.types.keys().cloned().collect();
    let new_types: BTreeSet<_> = new.types.keys().cloned().collect();
    for name in old_types.difference(&new_types) {
        changes.push(change(
            ApiChangeKind::Removed,
            format!("{module}::type {name}"),
            true,
            format!("removed public type `{module}.{name}`"),
        ));
    }
    for name in new_types.difference(&old_types) {
        changes.push(change(
            ApiChangeKind::Added,
            format!("{module}::type {name}"),
            false,
            format!("added public type `{module}.{name}`"),
        ));
    }
    for name in old_types.intersection(&new_types) {
        let old_type = &old.types[name];
        let new_type = &new.types[name];
        if old_type.signature != new_type.signature {
            changes.push(change(
                ApiChangeKind::Changed,
                format!("{module}::type {name}"),
                true,
                format!("changed public type `{module}.{name}`"),
            ));
        }
        compare_constructors(module, name, old_type, new_type, changes);
    }
}

fn compare_items(
    module: &str,
    kind: &str,
    old: &BTreeMap<String, String>,
    new: &BTreeMap<String, String>,
    changes: &mut Vec<ApiChange>,
) {
    let old_names: BTreeSet<_> = old.keys().cloned().collect();
    let new_names: BTreeSet<_> = new.keys().cloned().collect();
    for name in old_names.difference(&new_names) {
        changes.push(change(
            ApiChangeKind::Removed,
            format!("{module}::{kind} {name}"),
            true,
            format!("removed public {kind} `{module}.{name}`"),
        ));
    }
    for name in new_names.difference(&old_names) {
        changes.push(change(
            ApiChangeKind::Added,
            format!("{module}::{kind} {name}"),
            false,
            format!("added public {kind} `{module}.{name}`"),
        ));
    }
    for name in old_names.intersection(&new_names) {
        if old[name] != new[name] {
            changes.push(change(
                ApiChangeKind::Changed,
                format!("{module}::{kind} {name}"),
                true,
                format!("changed public {kind} `{module}.{name}`"),
            ));
        }
    }
}

fn compare_constructors(
    module: &str,
    type_name: &str,
    old: &TypeSurface,
    new: &TypeSurface,
    changes: &mut Vec<ApiChange>,
) {
    let old_names: BTreeSet<_> = old.constructors.keys().cloned().collect();
    let new_names: BTreeSet<_> = new.constructors.keys().cloned().collect();
    for name in old_names.difference(&new_names) {
        changes.push(change(
            ApiChangeKind::Removed,
            format!("{module}::type {type_name}::{name}"),
            true,
            format!("removed constructor `{module}.{name}`"),
        ));
    }
    // A constructor addition breaks exhaustive pattern matches.
    for name in new_names.difference(&old_names) {
        changes.push(change(
            ApiChangeKind::ConstructorAdded,
            format!("{module}::type {type_name}::{name}"),
            true,
            format!("added constructor `{module}.{name}` to existing type `{type_name}`"),
        ));
    }
    for name in old_names.intersection(&new_names) {
        if old.constructors[name] != new.constructors[name] {
            changes.push(change(
                ApiChangeKind::Changed,
                format!("{module}::type {type_name}::{name}"),
                true,
                format!("changed constructor `{module}.{name}`"),
            ));
        }
    }
}

fn change(kind: ApiChangeKind, path: String, breaking: bool, summary: String) -> ApiChange {
    ApiChange {
        kind,
        path,
        breaking,
        summary,
    }
}

fn parse_surface(bytes: &[u8]) -> Result<Surface> {
    let root: Value = serde_json::from_slice(bytes)?;
    let modules = root
        .get("modules")
        .and_then(Value::as_object)
        .context("missing `modules` object")?;
    let mut surface = Surface::default();
    for (module_name, module) in modules {
        let functions = parse_values(module, "functions", |item, vars| {
            let parameters = item
                .get("parameters")
                .and_then(Value::as_array)
                .context("function parameters")?;
            let mut signature = String::from("fn(");
            for (index, parameter) in parameters.iter().enumerate() {
                if index != 0 {
                    signature.push(',');
                }
                let label = parameter
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("_");
                signature.push_str(label);
                signature.push(':');
                signature.push_str(&type_signature(
                    parameter.get("type").context("parameter type")?,
                    vars,
                )?);
            }
            signature.push_str(")->");
            signature.push_str(&type_signature(
                item.get("return").context("function return")?,
                vars,
            )?);
            signature.push_str(&target_signature(item));
            Ok(signature)
        })?;
        let constants = parse_values(module, "constants", |item, vars| {
            Ok(format!(
                "{}{}",
                type_signature(item.get("type").context("constant type")?, vars)?,
                target_signature(item)
            ))
        })?;
        let aliases = parse_values(module, "type-aliases", |item, vars| {
            Ok(format!(
                "params={};{}",
                item.get("parameters").and_then(Value::as_u64).unwrap_or(0),
                type_signature(item.get("alias").context("alias type")?, vars)?
            ))
        })?;
        let mut output = ModuleSurface {
            functions,
            constants,
            aliases,
            types: BTreeMap::new(),
        };

        if let Some(types) = module.get("types").and_then(Value::as_object) {
            for (name, item) in types {
                let parameters = item.get("parameters").and_then(Value::as_u64).unwrap_or(0);
                let mut type_surface = TypeSurface {
                    signature: format!("params={parameters}"),
                    constructors: BTreeMap::new(),
                };
                if let Some(constructors) = item.get("constructors").and_then(Value::as_array) {
                    for constructor in constructors {
                        let constructor_name = constructor
                            .get("name")
                            .and_then(Value::as_str)
                            .context("constructor name")?;
                        let mut vars = HashMap::new();
                        let mut signature = String::new();
                        for parameter in constructor
                            .get("parameters")
                            .and_then(Value::as_array)
                            .context("constructor parameters")?
                        {
                            let label = parameter
                                .get("label")
                                .and_then(Value::as_str)
                                .unwrap_or("_");
                            signature.push_str(label);
                            signature.push(':');
                            signature.push_str(&type_signature(
                                parameter
                                    .get("type")
                                    .context("constructor parameter type")?,
                                &mut vars,
                            )?);
                            signature.push(';');
                        }
                        type_surface
                            .constructors
                            .insert(constructor_name.to_owned(), signature);
                    }
                }
                output.types.insert(name.to_owned(), type_surface);
            }
        }
        surface.modules.insert(module_name.to_owned(), output);
    }
    Ok(surface)
}

fn parse_values<F>(module: &Value, key: &str, mut signature: F) -> Result<BTreeMap<String, String>>
where
    F: FnMut(&Value, &mut HashMap<String, usize>) -> Result<String>,
{
    let mut output = BTreeMap::new();
    if let Some(items) = module.get(key).and_then(Value::as_object) {
        for (name, item) in items {
            output.insert(name.to_owned(), signature(item, &mut HashMap::new())?);
        }
    }
    Ok(output)
}

fn type_signature(value: &Value, vars: &mut HashMap<String, usize>) -> Result<String> {
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .context("type kind")?;
    Ok(match kind {
        "variable" => {
            let id = value.get("id").context("variable id")?.to_string();
            let next = vars.len();
            let canonical = *vars.entry(id).or_insert(next);
            format!("${canonical}")
        }
        "named" => {
            let package = value.get("package").and_then(Value::as_str).unwrap_or("");
            let module = value.get("module").and_then(Value::as_str).unwrap_or("");
            let name = value.get("name").and_then(Value::as_str).unwrap_or("?");
            let parameters = type_list(value.get("parameters"), vars)?;
            format!("named({package}:{module}:{name}{parameters})")
        }
        "fn" => {
            let parameters = type_list(value.get("parameters"), vars)?;
            let return_type = type_signature(value.get("return").context("fn return")?, vars)?;
            format!("fn{parameters}->{return_type}")
        }
        "tuple" => format!("tuple{}", type_list(value.get("elements"), vars)?),
        other => {
            // Preserve future interface kinds conservatively. Documentation is
            // stripped while the remaining shape is canonicalized.
            let fields = value.as_object().context("type must be an object")?;
            let fields = fields
                .iter()
                .filter(|(key, _)| {
                    !matches!(key.as_str(), "kind" | "documentation" | "deprecation")
                })
                .map(|(key, value)| Ok(format!("{key}:{}", canonical_value(value, vars)?)))
                .collect::<Result<Vec<_>>>()?;
            format!("{other}:{{{}}}", fields.join(","))
        }
    })
}

fn type_list(value: Option<&Value>, vars: &mut HashMap<String, usize>) -> Result<String> {
    let mut output = String::from("(");
    if let Some(values) = value.and_then(Value::as_array) {
        for (index, value) in values.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push_str(&type_signature(value, vars)?);
        }
    }
    output.push(')');
    Ok(output)
}

fn canonical_value(value: &Value, vars: &mut HashMap<String, usize>) -> Result<String> {
    if value.get("kind").is_some() {
        return type_signature(value, vars);
    }
    Ok(match value {
        Value::Array(values) => {
            let values = values
                .iter()
                .map(|value| canonical_value(value, vars))
                .collect::<Result<Vec<_>>>()?;
            format!("[{}]", values.join(","))
        }
        Value::Object(values) => {
            let values = values
                .iter()
                .filter(|(key, _)| !matches!(key.as_str(), "documentation" | "deprecation"))
                .map(|(key, value)| Ok(format!("{key}:{}", canonical_value(value, vars)?)))
                .collect::<Result<Vec<_>>>()?;
            format!("{{{}}}", values.join(","))
        }
        _ => value.to_string(),
    })
}

fn target_signature(item: &Value) -> String {
    let implementations = item.get("implementations");
    let erlang = implementations
        .and_then(|value| value.get("can-run-on-erlang"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let javascript = implementations
        .and_then(|value| value.get("can-run-on-javascript"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    format!(";targets=erlang:{erlang},javascript:{javascript}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn interface(module: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"modules": {"one": module}})).unwrap()
    }

    fn module(functions: Value, types: Value) -> Value {
        json!({"functions": functions, "constants": {}, "type-aliases": {}, "types": types})
    }

    fn function(variable: u64, label: Value, erlang: bool) -> Value {
        json!({
            "documentation": "ignored",
            "parameters": [{"label": label, "type": {"kind": "variable", "id": variable}}],
            "return": {"kind": "variable", "id": variable},
            "implementations": {"can-run-on-erlang": erlang, "can-run-on-javascript": true}
        })
    }

    #[test]
    fn type_variable_rename_and_docs_are_ignored() {
        let old = interface(module(
            json!({"map": function(0, Value::Null, true)}),
            json!({}),
        ));
        let new = interface(module(
            json!({"map": function(91, Value::Null, true)}),
            json!({}),
        ));
        let diff = compare(&old, &new).unwrap();
        assert_eq!(diff.impact, Bump::None);
    }

    #[test]
    fn labels_and_target_support_are_breaking() {
        let old = interface(module(
            json!({"map": function(0, json!("value"), true)}),
            json!({}),
        ));
        let new = interface(module(
            json!({"map": function(0, json!("item"), false)}),
            json!({}),
        ));
        let diff = compare(&old, &new).unwrap();
        assert_eq!(diff.impact, Bump::Major);
    }

    #[test]
    fn public_item_addition_is_minor() {
        let old = interface(module(json!({}), json!({})));
        let new = interface(module(
            json!({"new": function(0, Value::Null, true)}),
            json!({}),
        ));
        assert_eq!(compare(&old, &new).unwrap().impact, Bump::Minor);
    }

    #[test]
    fn constructor_addition_is_breaking() {
        let old_type = json!({"parameters": 0, "constructors": [{"name": "A", "parameters": []}]});
        let new_type = json!({"parameters": 0, "constructors": [
            {"name": "A", "parameters": []}, {"name": "B", "parameters": []}
        ]});
        let old = interface(module(json!({}), json!({"Choice": old_type})));
        let new = interface(module(json!({}), json!({"Choice": new_type})));
        let diff = compare(&old, &new).unwrap();
        assert_eq!(diff.impact, Bump::Major);
        assert_eq!(diff.changes[0].kind, ApiChangeKind::ConstructorAdded);
    }

    #[test]
    fn removals_type_changes_alias_changes_and_opaque_changes_are_breaking() {
        let empty_module = module(json!({}), json!({}));
        let function_removed = (
            interface(module(
                json!({"gone": function(0, Value::Null, true)}),
                json!({}),
            )),
            interface(empty_module.clone()),
        );
        let type_parameters_changed = (
            interface(module(
                json!({}),
                json!({"Box": {"parameters": 1, "constructors": []}}),
            )),
            interface(module(
                json!({}),
                json!({"Box": {"parameters": 2, "constructors": []}}),
            )),
        );
        let opaque_became_public = (
            interface(module(
                json!({}),
                json!({"Secret": {"parameters": 0, "constructors": []}}),
            )),
            interface(module(
                json!({}),
                json!({"Secret": {"parameters": 0, "constructors": [{"name": "Secret", "parameters": []}]}}),
            )),
        );
        let alias_changed = (
            interface(json!({
                "functions": {}, "constants": {}, "types": {},
                "type-aliases": {"Id": {"parameters": 0, "alias": {"kind": "named", "name": "Int", "package": "", "module": "gleam", "parameters": []}}}
            })),
            interface(json!({
                "functions": {}, "constants": {}, "types": {},
                "type-aliases": {"Id": {"parameters": 0, "alias": {"kind": "named", "name": "String", "package": "", "module": "gleam", "parameters": []}}}
            })),
        );
        for (old, new) in [
            function_removed,
            type_parameters_changed,
            opaque_became_public,
            alias_changed,
        ] {
            assert_eq!(compare(&old, &new).unwrap().impact, Bump::Major);
        }

        let old = serde_json::to_vec(&json!({"modules": {"one": empty_module}})).unwrap();
        let new = serde_json::to_vec(&json!({"modules": {}})).unwrap();
        assert_eq!(compare(&old, &new).unwrap().impact, Bump::Major);
    }

    #[test]
    fn every_public_surface_kind_reports_add_remove_and_change() {
        let named = |name: &str| {
            json!({
                "kind": "named",
                "package": "gleam_stdlib",
                "module": "gleam",
                "name": name,
                "parameters": []
            })
        };
        let old = serde_json::to_vec(&json!({
            "modules": {
                "removed_module": module(json!({}), json!({})),
                "shared": {
                    "functions": {
                        "removed": {"parameters": [], "return": named("Int")},
                        "changed": {"parameters": [], "return": named("Int")},
                        "same": {"parameters": [], "return": named("Int")}
                    },
                    "constants": {
                        "REMOVED": {"type": named("Int")},
                        "CHANGED": {"type": named("Int")},
                        "SAME": {"type": named("Int")}
                    },
                    "type-aliases": {
                        "Removed": {"parameters": 0, "alias": named("Int")},
                        "Changed": {"parameters": 0, "alias": named("Int")},
                        "Same": {"parameters": 0, "alias": named("Int")}
                    },
                    "types": {
                        "Removed": {"parameters": 0, "constructors": []},
                        "Changed": {"parameters": 0, "constructors": []},
                        "Choice": {"parameters": 0, "constructors": [
                            {"name": "Removed", "parameters": []},
                            {"name": "Changed", "parameters": [
                                {"label": null, "type": named("Int")}
                            ]},
                            {"name": "Same", "parameters": []}
                        ]},
                        "Same": {"parameters": 0, "constructors": []}
                    }
                }
            }
        }))
        .unwrap();
        let new = serde_json::to_vec(&json!({
            "modules": {
                "added_module": module(json!({}), json!({})),
                "shared": {
                    "functions": {
                        "added": {"parameters": [], "return": named("Int")},
                        "changed": {"parameters": [], "return": named("String")},
                        "same": {"parameters": [], "return": named("Int")}
                    },
                    "constants": {
                        "ADDED": {"type": named("Int")},
                        "CHANGED": {"type": named("String")},
                        "SAME": {"type": named("Int")}
                    },
                    "type-aliases": {
                        "Added": {"parameters": 0, "alias": named("Int")},
                        "Changed": {"parameters": 1, "alias": named("Int")},
                        "Same": {"parameters": 0, "alias": named("Int")}
                    },
                    "types": {
                        "Added": {"parameters": 0, "constructors": []},
                        "Changed": {"parameters": 1, "constructors": []},
                        "Choice": {"parameters": 0, "constructors": [
                            {"name": "Added", "parameters": []},
                            {"name": "Changed", "parameters": [
                                {"label": "value", "type": named("String")}
                            ]},
                            {"name": "Same", "parameters": []}
                        ]},
                        "Same": {"parameters": 0, "constructors": []}
                    }
                }
            }
        }))
        .unwrap();

        let diff = compare(&old, &new).unwrap();
        assert_eq!(diff.status, ApiStatus::Changed);
        assert_eq!(diff.impact, Bump::Major);
        let paths: BTreeSet<_> = diff
            .changes
            .iter()
            .map(|change| change.path.as_str())
            .collect();
        for path in [
            "module added_module",
            "module removed_module",
            "shared::function added",
            "shared::function removed",
            "shared::function changed",
            "shared::constant ADDED",
            "shared::constant REMOVED",
            "shared::constant CHANGED",
            "shared::type alias Added",
            "shared::type alias Removed",
            "shared::type alias Changed",
            "shared::type Added",
            "shared::type Removed",
            "shared::type Changed",
            "shared::type Choice::Added",
            "shared::type Choice::Removed",
            "shared::type Choice::Changed",
        ] {
            assert!(paths.contains(path), "missing {path}: {:#?}", diff.changes);
        }
        assert!(
            diff.changes
                .iter()
                .find(|change| change.path == "module added_module")
                .is_some_and(|change| !change.breaking)
        );
        assert!(
            diff.changes
                .iter()
                .find(|change| change.path == "shared::type Choice::Added")
                .is_some_and(|change| {
                    change.breaking && change.kind == ApiChangeKind::ConstructorAdded
                })
        );
    }

    #[test]
    fn nested_named_function_tuple_and_future_types_are_canonicalized_conservatively() {
        let surface = |variable: u64, docs: &str, future_flag: bool| {
            serde_json::to_vec(&json!({
                "modules": {"one": {
                    "functions": {"complex": {
                        "documentation": docs,
                        "parameters": [
                            {"type": {"kind": "tuple", "elements": [
                                {"kind": "variable", "id": variable},
                                {"kind": "named", "package": "gleam_stdlib", "module": "gleam/list", "name": "List", "parameters": [
                                    {"kind": "variable", "id": variable}
                                ]}
                            ]}},
                            {"label": "mapper", "type": {"kind": "fn", "parameters": [
                                {"kind": "variable", "id": variable}
                            ], "return": {"kind": "variable", "id": variable}}}
                        ],
                        "return": {
                            "kind": "future-kind",
                            "flag": future_flag,
                            "documentation": docs,
                            "deprecation": "ignored",
                            "nested": {"kind": "variable", "id": variable},
                            "values": [1, true, null]
                        },
                        "implementations": {"can-run-on-erlang": true, "can-run-on-javascript": false}
                    }},
                    "constants": {}, "type-aliases": {}, "types": {}
                }}
            }))
            .unwrap()
        };

        let old = surface(7, "old docs", true);
        let renamed = surface(999, "new docs", true);
        let changed = surface(999, "new docs", false);
        assert_eq!(compare(&old, &renamed).unwrap().impact, Bump::None);
        assert_eq!(compare(&old, &changed).unwrap().impact, Bump::Major);
    }

    #[test]
    fn malformed_interface_shapes_are_rejected_instead_of_guessed() {
        let named = json!({"kind": "named", "name": "Int"});
        let cases = [
            vec![b'{'],
            serde_json::to_vec(&json!({})).unwrap(),
            serde_json::to_vec(&json!({"modules": []})).unwrap(),
            interface(json!({
                "functions": {"bad": {"return": named}},
                "constants": {}, "type-aliases": {}, "types": {}
            })),
            interface(json!({
                "functions": {"bad": {"parameters": [{}], "return": named}},
                "constants": {}, "type-aliases": {}, "types": {}
            })),
            interface(json!({
                "functions": {"bad": {"parameters": []}},
                "constants": {}, "type-aliases": {}, "types": {}
            })),
            interface(json!({
                "functions": {}, "constants": {"BAD": {}}, "type-aliases": {}, "types": {}
            })),
            interface(json!({
                "functions": {}, "constants": {}, "type-aliases": {"Bad": {}}, "types": {}
            })),
            interface(json!({
                "functions": {}, "constants": {}, "type-aliases": {},
                "types": {"Bad": {"constructors": [{"parameters": []}]}}
            })),
            interface(json!({
                "functions": {}, "constants": {}, "type-aliases": {},
                "types": {"Bad": {"constructors": [{"name": "Bad"}]}}
            })),
            interface(json!({
                "functions": {}, "constants": {}, "type-aliases": {},
                "types": {"Bad": {"constructors": [{"name": "Bad", "parameters": [{}]}]}}
            })),
            interface(json!({
                "functions": {}, "constants": {"BAD": {"type": {}}},
                "type-aliases": {}, "types": {}
            })),
            interface(json!({
                "functions": {}, "constants": {"BAD": {"type": {"kind": "variable"}}},
                "type-aliases": {}, "types": {}
            })),
            interface(json!({
                "functions": {}, "constants": {"BAD": {"type": {"kind": "fn", "parameters": []}}},
                "type-aliases": {}, "types": {}
            })),
        ];
        let valid = interface(module(json!({}), json!({})));
        for (index, malformed) in cases.into_iter().enumerate() {
            assert!(
                compare(&malformed, &valid).is_err(),
                "malformed case {index} was accepted"
            );
            assert!(
                compare(&valid, &malformed).is_err(),
                "malformed new case {index} was accepted"
            );
        }
    }
}
