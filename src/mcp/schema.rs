//! Input validation against the schema a tool advertises.
//!
//! This is deliberately **not** a JSON Schema engine. A complete implementation
//! is a large dependency tree (26 crates for `jsonschema` at the time of
//! writing) for a check that is a convenience, not a security boundary — the
//! tool still validates, because the schema is one the upstream chose to
//! publish.
//!
//! So it enforces the two rules that can be decided exactly, and ignores every
//! other keyword. That asymmetry is the point: an unsupported keyword means
//! "the gateway has no opinion", never "reject a call the schema would have
//! accepted".
//!
//! - `params.arguments` must be an object, or absent.
//! - every name in the advertised `inputSchema.required` must be present.
//!
//! Schemas are learned from `tools/list` responses and cached, so there is one
//! source of truth: the tool's own manifest.

use std::{sync::Arc, time::Duration};

use serde_json::Value;

use crate::auth::cache::TtlCache;

/// Matches the tool cap the policy layer enforces; the cache must not be the
/// smaller of the two bounds.
const MAX_TOOLS: usize = 4_096;

/// The part of a tool's `inputSchema` the gateway understands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ToolShape {
    required: Vec<String>,
}

impl ToolShape {
    fn from_schema(schema: &Value) -> Self {
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        Self { required }
    }

    fn check(&self, arguments: Option<&Value>) -> Result<(), String> {
        let present = match arguments {
            None => None,
            Some(Value::Object(map)) => Some(map),
            // The protocol defines arguments as an object; an array or scalar
            // is malformed regardless of the schema.
            Some(_) => return Err("arguments must be a JSON object".to_owned()),
        };

        for name in &self.required {
            let missing = present.is_none_or(|map| !map.contains_key(name));
            if missing {
                return Err(format!("missing required argument `{name}`"));
            }
        }

        Ok(())
    }
}

/// Cached shapes, keyed by `(upstream id, tool name)`.
///
/// An empty TTL disables the cache entirely, which disables validation: a
/// gateway that cannot remember a schema has nothing to check against.
pub(crate) struct SchemaCache {
    shapes: TtlCache<(String, String), Arc<ToolShape>>,
}

impl SchemaCache {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            shapes: TtlCache::with_capacity(ttl, MAX_TOOLS),
        }
    }

    pub(crate) fn get(&self, upstream: &str, tool: &str) -> Option<Arc<ToolShape>> {
        self.shapes
            .get(&(upstream.to_owned(), tool.to_owned()))
    }

    fn insert(&self, upstream: &str, tool: &str, shape: ToolShape) {
        self.shapes
            .insert((upstream.to_owned(), tool.to_owned()), Arc::new(shape));
    }
}

/// Records every tool schema in a `tools/list` result. Unknown shapes are
/// ignored rather than treated as an error: a server that publishes no schema
/// simply gets no gateway-side validation.
pub(crate) fn learn(list: &Value, upstream: &str, cache: &SchemaCache) {
    let Some(tools) = list
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
    else {
        return;
    };

    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };

        if name.is_empty() || name.len() > 256 {
            continue;
        }

        let Some(schema) = tool.get("inputSchema") else {
            continue;
        };

        cache.insert(upstream, name, ToolShape::from_schema(schema));
    }
}

/// Applies the learned shape to a call. Constructed per policy-checked
/// request; holds borrows only.
pub(crate) struct SchemaValidator<'a> {
    cache: &'a SchemaCache,
    upstream: &'a str,
}

impl<'a> SchemaValidator<'a> {
    pub(crate) fn new(cache: &'a SchemaCache, upstream: &'a str) -> Self {
        Self { cache, upstream }
    }
}

impl super::CallValidator for SchemaValidator<'_> {
    fn validate(&self, tool: &str, arguments: Option<&Value>) -> Result<(), String> {
        // No schema learned yet (cold cache, or the caller never listed):
        // fail open. The tool validates, and rejecting on the absence of
        // evidence would break a perfectly good call.
        match self.cache.get(self.upstream, tool) {
            Some(shape) => shape.check(arguments),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cache() -> SchemaCache {
        SchemaCache::new(Duration::from_secs(60))
    }

    fn list() -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search_tickets",
                        "inputSchema": {
                            "type": "object",
                            "required": ["query"],
                            "properties": {"query": {"type": "string"}}
                        }
                    },
                    {
                        "name": "health",
                        "inputSchema": {"type": "object"}
                    }
                ]
            }
        })
    }

    fn validate(
        cache: &SchemaCache,
        upstream: &str,
        tool: &str,
        arguments: Option<Value>,
    ) -> Result<(), String> {
        use super::super::CallValidator as _;

        SchemaValidator::new(cache, upstream).validate(tool, arguments.as_ref())
    }

    #[test]
    fn learns_required_fields_from_a_tool_list() {
        let cache = cache();
        learn(&list(), "upstream", &cache);

        let shape = cache
            .get("upstream", "search_tickets")
            .expect("learned");
        assert_eq!(shape.required, vec!["query".to_owned()]);
        assert!(
            cache
                .get("upstream", "health")
                .is_some()
        );
    }

    #[test]
    fn learns_nothing_from_an_error_envelope() {
        let cache = cache();
        learn(
            &json!({"jsonrpc": "2.0", "error": {"code": -32601}}),
            "u",
            &cache,
        );

        assert!(
            cache
                .get("u", "search_tickets")
                .is_none()
        );
    }

    #[test]
    fn rejects_a_missing_required_argument() {
        let cache = cache();
        learn(&list(), "u", &cache);

        let reason = validate(&cache, "u", "search_tickets", Some(json!({"q": "x"})))
            .expect_err("missing query");

        assert_eq!(reason, "missing required argument `query`");
    }

    #[test]
    fn rejects_arguments_that_are_not_an_object() {
        let cache = cache();
        learn(&list(), "u", &cache);

        let reason = validate(&cache, "u", "search_tickets", Some(json!(["query"])))
            .expect_err("arguments are not an object");

        assert_eq!(reason, "arguments must be a JSON object");
    }

    #[test]
    fn accepts_absent_arguments_when_nothing_is_required() {
        let cache = cache();
        learn(&list(), "u", &cache);

        assert!(validate(&cache, "u", "health", None).is_ok());
    }

    #[test]
    fn rejects_absent_arguments_when_a_field_is_required() {
        let cache = cache();
        learn(&list(), "u", &cache);

        assert!(validate(&cache, "u", "search_tickets", None).is_err());
    }

    #[test]
    fn ignores_keywords_it_does_not_implement() {
        let cache = cache();
        let list = json!({
            "result": {"tools": [{
                "name": "strict",
                "inputSchema": {
                    "type": "object",
                    "required": ["a"],
                    "oneOf": [{"required": ["never"]}],
                    "properties": {"a": {"type": "string", "format": "uuid"}}
                }
            }]}
        });
        learn(&list, "u", &cache);

        // The unsupported keywords must not turn a call the schema would have
        // accepted into a rejection.
        assert!(validate(&cache, "u", "strict", Some(json!({"a": "not-a-uuid"}))).is_ok());
    }

    #[test]
    fn an_unknown_tool_fails_open() {
        let cache = cache();

        assert!(validate(&cache, "u", "never_listed", Some(json!({}))).is_ok());
    }

    #[test]
    fn an_expired_shape_stops_validating() {
        let cache = SchemaCache::new(Duration::ZERO);
        learn(&list(), "u", &cache);

        assert!(
            cache
                .get("u", "search_tickets")
                .is_none()
        );
        assert!(validate(&cache, "u", "search_tickets", Some(json!({}))).is_ok());
    }

    #[test]
    fn another_upstream_cannot_reuse_a_shape() {
        let cache = cache();
        learn(&list(), "a", &cache);

        assert!(validate(&cache, "b", "search_tickets", Some(json!({}))).is_ok());
    }
}
