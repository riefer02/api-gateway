//! MCP-aware policy: the smallest amount of JSON-RPC the gateway needs to
//! enforce tool allowlists and filter discovery responses.
//!
//! This is deliberately not an MCP implementation. The gateway reads the
//! envelope, decides whether a tool may be called, and leaves every protocol
//! semantic to the upstream server.

pub(crate) mod schema;

use std::collections::{HashMap, HashSet};

use serde::{
    Deserialize, Serialize,
    de::{self, Deserializer, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use std::fmt;

const MAX_ROLES: usize = 256;
const MAX_TOOLS_PER_ROLE: usize = 1_024;
const MAX_NAME_LEN: usize = 256;
const MAX_BATCH: usize = 64;
const MAX_TOTAL_TOOLS: usize = 4_096;

/// Stored on the route as JSONB, validated on write and again at compile time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolPolicy {
    #[serde(default)]
    pub(crate) mode: ToolMode,
    /// Role name to tool names. `*` as a role matches every caller; `*` as a
    /// tool name allows every tool for that role.
    #[serde(default)]
    pub(crate) roles: HashMap<String, Vec<String>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ToolMode {
    /// Do not parse the body; the upstream owns tool authorization.
    #[default]
    Off,
    /// Only tools granted to one of the caller's roles may be called and listed.
    AllowList,
}

impl ToolPolicy {
    pub(crate) fn is_enforcing(&self) -> bool {
        self.mode == ToolMode::AllowList
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.roles.len() > MAX_ROLES {
            return Err(format!("tool policy may name at most {MAX_ROLES} roles"));
        }

        if self
            .roles
            .values()
            .map(Vec::len)
            .sum::<usize>()
            > MAX_TOTAL_TOOLS
        {
            return Err(format!(
                "tool policy may name at most {MAX_TOTAL_TOOLS} tool grants"
            ));
        }

        for (role, tools) in &self.roles {
            validate_name("role", role)?;

            if tools.len() > MAX_TOOLS_PER_ROLE {
                return Err(format!(
                    "role `{role}` may name at most {MAX_TOOLS_PER_ROLE} tools"
                ));
            }

            for tool in tools {
                validate_name("tool", tool)?;
            }
        }

        if self.is_enforcing() && self.roles.is_empty() {
            return Err("an allow-list policy must grant at least one role".to_owned());
        }

        Ok(())
    }

    /// Resolves the caller's roles into a concrete tool set.
    pub(crate) fn allowed_tools(&self, roles: &HashSet<String>) -> AllowedTools {
        if !self.is_enforcing() {
            return AllowedTools::All;
        }

        let mut allowed = HashSet::new();

        for (role, tools) in &self.roles {
            if role != "*" && !roles.contains(role) {
                continue;
            }

            if tools.iter().any(|tool| tool == "*") {
                return AllowedTools::All;
            }

            allowed.extend(tools.iter().cloned());
        }

        AllowedTools::Set(allowed)
    }
}

fn validate_name(kind: &str, value: &str) -> Result<(), String> {
    let value = value.trim();

    if value.is_empty() {
        return Err(format!("{kind} name must not be empty"));
    }

    if value.len() > MAX_NAME_LEN {
        return Err(format!("{kind} name exceeds {MAX_NAME_LEN} characters"));
    }

    if value.chars().any(char::is_control) {
        return Err(format!("{kind} name must not contain control characters"));
    }

    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) enum AllowedTools {
    All,
    Set(HashSet<String>),
}

impl AllowedTools {
    pub(crate) fn allows(&self, tool: &str) -> bool {
        match self {
            Self::All => true,
            Self::Set(tools) => tools.contains(tool),
        }
    }

    pub(crate) fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

/// Where a learned tool schema is recorded.
///
/// A named pair rather than a tuple so the call site says which string is the
/// upstream, and so schema pinning can be added here without changing the
/// filter's shape again.
#[derive(Clone)]
pub(crate) struct SchemaSink {
    pub(crate) cache: std::sync::Arc<schema::SchemaCache>,
    /// The upstream the listed tools belong to; schemas are scoped by it.
    pub(crate) upstream: String,
}

/// Response filtering instructions for a `tools/list` request.
#[derive(Clone)]
pub(crate) struct ToolFilter {
    pub(crate) allowed: AllowedTools,
    /// `tools/list` must return a `result.tools` array; discovery and error
    /// envelopes must pass through unchanged.
    pub(crate) require_tools: bool,
    /// `None` disables schema learning, and therefore input validation.
    pub(crate) schemas: Option<SchemaSink>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum McpError {
    /// The body is not a single JSON-RPC request or a bounded batch.
    Malformed(&'static str),
    /// The request calls a tool this caller may not use.
    Denied { tool: String, id: Option<Value> },
}

impl McpError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Malformed(reason) => format!("invalid MCP request: {reason}"),
            Self::Denied { tool, .. } => {
                format!("tool `{tool}` is not permitted for this user")
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcMessage {
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

/// One `tools/call` in a request, kept so its arguments can be checked
/// against the tool's advertised schema before the upstream sees them.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToolCall {
    pub(crate) name: String,
    pub(crate) arguments: Option<Value>,
    /// The JSON-RPC id, so a rejection answers the right request.
    pub(crate) id: Option<Value>,
}

/// A request the gateway understood well enough to audit and authorize.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EvaluatedRequest {
    pub(crate) method: String,
    pub(crate) tool: Option<String>,
    /// True if any message in the request (including a batch) asked for tools.
    pub(crate) wants_tools_list: bool,
    pub(crate) batch: bool,
    pub(crate) protocol_version: Option<String>,
    /// Every `tools/call` in the request, in order. Batches may hold several.
    pub(crate) calls: Vec<ToolCall>,
}

/// Parses the request, enforces the tool policy, and returns the method and tool
/// for auditing. Called only when the route has an enforcing policy.
pub(crate) fn evaluate(body: &[u8], allowed: &AllowedTools) -> Result<EvaluatedRequest, McpError> {
    let messages = parse(body)?;
    let batch = messages.len() > 1;
    let mut audit_method: Option<String> = None;
    let mut audit_tool: Option<String> = None;
    let mut wants_tools_list = false;
    let mut protocol_version = None;
    let mut calls = Vec::new();

    for message in messages {
        if message.jsonrpc != "2.0" {
            return Err(McpError::Malformed("jsonrpc must be `2.0`"));
        }

        validate_name("method", &message.method)
            .map_err(|_| McpError::Malformed("invalid method name"))?;

        if protocol_version.is_none() {
            protocol_version = message
                .params
                .as_ref()
                .and_then(|params| params.get("_meta"))
                .and_then(|meta| meta.get("io.modelcontextprotocol/protocolVersion"))
                .and_then(Value::as_str)
                .map(str::to_owned);
        }

        if message.method == "tools/list" {
            wants_tools_list = true;
        }

        if message.method == "tools/call" {
            let tool = message
                .params
                .as_ref()
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .ok_or(McpError::Malformed("tools/call requires params.name"))?;

            validate_name("tool", tool).map_err(|_| McpError::Malformed("invalid tool name"))?;

            if !allowed.allows(tool) {
                return Err(McpError::Denied {
                    tool: tool.to_owned(),
                    id: message.id.clone(),
                });
            }

            calls.push(ToolCall {
                name: tool.to_owned(),
                arguments: message
                    .params
                    .as_ref()
                    .and_then(|params| params.get("arguments"))
                    .cloned(),
                id: message.id.clone(),
            });

            // Prefer a tool call for audit attribution: a batch may also carry
            // initialize/notifications that would otherwise hide the call.
            if audit_tool.is_none() {
                audit_method = Some("tools/call".to_owned());
                audit_tool = Some(tool.to_owned());
            }
        } else if audit_method.is_none() {
            audit_method = Some(message.method);
        }
    }

    Ok(EvaluatedRequest {
        method: audit_method.ok_or(McpError::Malformed("empty request"))?,
        tool: audit_tool,
        wants_tools_list,
        batch,
        protocol_version,
        calls,
    })
}

fn parse(body: &[u8]) -> Result<Vec<RpcMessage>, McpError> {
    if body.is_empty() {
        return Err(McpError::Malformed("empty body"));
    }

    // `serde_json::Value` keeps the last duplicate key, while the raw body is
    // forwarded. An upstream that keeps the first key would execute a
    // different tool than the one authorized here, so duplicates are refused.
    if serde_json::from_slice::<NoDuplicateKeys>(body).is_err() {
        return Err(McpError::Malformed("duplicate object key or invalid JSON"));
    }

    if body.first() == Some(&b'[') {
        let messages: Vec<RpcMessage> =
            serde_json::from_slice(body).map_err(|_| McpError::Malformed("invalid JSON batch"))?;

        if messages.is_empty() || messages.len() > MAX_BATCH {
            return Err(McpError::Malformed("batch size is out of range"));
        }

        Ok(messages)
    } else {
        let message: RpcMessage =
            serde_json::from_slice(body).map_err(|_| McpError::Malformed("invalid JSON"))?;
        Ok(vec![message])
    }
}

/// A JSON-RPC error body. Server errors use the reserved implementation band.
pub(crate) fn rpc_error_body(code: i64, id: Option<Value>, message: &str) -> Vec<u8> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
        }
    });

    serde_json::to_vec(&body).unwrap_or_default()
}

/// A denial the model can render. HTTP 200 is deliberate: a non-2xx response
/// is a transport failure to most MCP clients, not a tool error.
pub(crate) fn denial_body(id: Option<Value>, message: &str) -> Vec<u8> {
    rpc_error_body(-32000, id, message)
}

/// The spec's header/body disagreement error (`-32020`), sent as a 400 with a
/// JSON-RPC body so a compliant client sees a protocol error, not an HTML/proxy
/// envelope.
pub(crate) fn header_mismatch_body(message: &str) -> Vec<u8> {
    rpc_error_body(-32020, None, message)
}

/// Removes tools the caller cannot use from a `tools/list` response. Returns
/// `None` when the caller must not receive the body: an unparseable response or
/// a `tools/list` result that carries no tool array. Discovery and error
/// envelopes pass through unchanged.
pub(crate) fn filter_tool_list(body: &[u8], filter: &ToolFilter) -> Option<Vec<u8>> {
    if filter.allowed.is_all() {
        return Some(body.to_vec());
    }

    let mut value: Value = serde_json::from_slice(body).ok()?;

    // Learn before filtering: the shapes belong to the tools that were listed,
    // whether or not this caller may see them, and a filtered list still tells
    // the gateway what a permitted tool requires.
    if let Some(sink) = &filter.schemas {
        schema::learn(&value, &sink.upstream, &sink.cache);
    }

    if !filter_value(&mut value, filter) {
        return None;
    }

    serde_json::to_vec(&value).ok()
}

fn filter_value(value: &mut Value, filter: &ToolFilter) -> bool {
    if let Some(array) = value.as_array_mut() {
        let mut found = false;

        for item in array {
            found |= filter_object(item, filter);
        }

        return found || !filter.require_tools;
    }

    filter_object(value, filter)
}

fn filter_object(value: &mut Value, filter: &ToolFilter) -> bool {
    let Some(object) = value.as_object_mut() else {
        return !filter.require_tools;
    };

    // An error envelope for tools/list is a legitimate response; it carries no
    // tool catalogue and must not be replaced with a gateway 502.
    if object.contains_key("error") {
        return true;
    }

    let Some(result) = object
        .get_mut("result")
        .and_then(Value::as_object_mut)
    else {
        return !filter.require_tools;
    };

    let Some(tools) = result
        .get_mut("tools")
        .and_then(Value::as_array_mut)
    else {
        return !filter.require_tools;
    };

    tools.retain(|tool| {
        tool.get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| filter.allowed.allows(name))
    });

    // A filtered list is a per-user authorization artifact. Never let a shared
    // cache reuse it, and drop the now-wrong freshness hint.
    result.insert("cacheScope".to_owned(), Value::String("private".to_owned()));
    result.remove("ttlMs");

    true
}

/// A validation-only deserializer that rejects repeated object keys at any
/// depth. JSON-RPC bodies are small; a second parse is cheaper than a parser
/// differential between the gateway and the upstream.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateKeys)?;
        Ok(NoDuplicateKeys)
    }
}

impl<'de> Visitor<'de> for NoDuplicateKeys {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element::<NoDuplicateKeys>()?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();

        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate object key"));
            }

            map.next_value::<NoDuplicateKeys>()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(roles: &[&str]) -> HashSet<String> {
        roles
            .iter()
            .map(|role| (*role).to_owned())
            .collect()
    }

    fn policy(mode: ToolMode, grants: &[(&str, &[&str])]) -> ToolPolicy {
        ToolPolicy {
            mode,
            roles: grants
                .iter()
                .map(|(role, tools)| {
                    (
                        (*role).to_owned(),
                        tools
                            .iter()
                            .map(|tool| (*tool).to_owned())
                            .collect(),
                    )
                })
                .collect(),
        }
    }

    fn call(tool: &str) -> Vec<u8> {
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": tool, "arguments": {} }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn off_mode_does_not_inspect_the_body() {
        let policy = policy(ToolMode::Off, &[]);
        assert!(!policy.is_enforcing());
        assert!(matches!(
            policy.allowed_tools(&roles(&[])),
            AllowedTools::All
        ));
    }

    #[test]
    fn allow_list_grants_only_listed_tools() {
        let policy = policy(
            ToolMode::AllowList,
            &[("support", &["search_tickets"]), ("admin", &["*"])],
        );
        policy.validate().expect("valid policy");

        let allowed = policy.allowed_tools(&roles(&["support"]));
        assert!(allowed.allows("search_tickets"));
        assert!(!allowed.allows("delete_ticket"));

        let admin = policy.allowed_tools(&roles(&["admin"]));
        assert!(matches!(admin, AllowedTools::All));
    }

    #[test]
    fn an_unknown_role_gets_nothing() {
        let policy = policy(ToolMode::AllowList, &[("support", &["search"])]);
        let allowed = policy.allowed_tools(&roles(&["contractor"]));

        assert!(!allowed.allows("search"));
    }

    #[test]
    fn wildcard_role_applies_to_everyone() {
        let policy = policy(ToolMode::AllowList, &[("*", &["search"])]);
        let allowed = policy.allowed_tools(&roles(&[]));

        assert!(allowed.allows("search"));
    }

    #[test]
    fn denies_an_unlisted_tool() {
        let policy = policy(ToolMode::AllowList, &[("support", &["search"])]);
        let allowed = policy.allowed_tools(&roles(&["support"]));

        let error = evaluate(&call("delete_ticket"), &allowed).expect_err("denied");
        assert_eq!(
            error,
            McpError::Denied {
                tool: "delete_ticket".to_owned(),
                id: Some(json!(7)),
            }
        );
    }

    #[test]
    fn allows_a_listed_tool() {
        let policy = policy(ToolMode::AllowList, &[("support", &["search"])]);
        let allowed = policy.allowed_tools(&roles(&["support"]));

        let evaluated = evaluate(&call("search"), &allowed).expect("allowed");
        assert_eq!(evaluated.tool.as_deref(), Some("search"));
        assert_eq!(evaluated.method, "tools/call");
    }

    #[test]
    fn rejects_malformed_and_oversized_batches() {
        let allowed = AllowedTools::All;

        assert!(matches!(
            evaluate(b"not json", &allowed),
            Err(McpError::Malformed(_))
        ));
        assert!(matches!(
            evaluate(b"[]", &allowed),
            Err(McpError::Malformed(_))
        ));

        let batch = serde_json::to_vec(
            &(0..=MAX_BATCH)
                .map(|id| {
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/list"
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        assert!(matches!(
            evaluate(&batch, &allowed),
            Err(McpError::Malformed("batch size is out of range"))
        ));
    }

    #[test]
    fn rejects_duplicate_object_keys_at_any_depth() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","name":"delete"}}"#;

        assert!(matches!(
            evaluate(body, &AllowedTools::All),
            Err(McpError::Malformed(_))
        ));
    }

    #[test]
    fn enforces_every_call_in_a_batch() {
        let policy = policy(ToolMode::AllowList, &[("support", &["search"])]);
        let allowed = policy.allowed_tools(&roles(&["support"]));

        let batch = json!([
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete"}}
        ])
        .to_string()
        .into_bytes();

        assert!(matches!(
            evaluate(&batch, &allowed),
            Err(McpError::Denied { tool, .. }) if tool == "delete"
        ));
    }

    #[test]
    fn filters_tools_from_a_list_response() {
        let allowed = AllowedTools::Set(HashSet::from(["search".to_owned()]));
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "search", "description": "ok"},
                    {"name": "delete", "description": "no"}
                ],
                "nextCursor": "abc"
            }
        })
        .to_string()
        .into_bytes();

        let filter = ToolFilter {
            allowed,
            require_tools: true,
            schemas: None,
        };
        let filtered = filter_tool_list(&body, &filter).expect("filtered");
        let value: Value = serde_json::from_slice(&filtered).unwrap();
        let tools = value["result"]["tools"]
            .as_array()
            .unwrap();

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "search");
        assert_eq!(value["result"]["nextCursor"], "abc");
        assert_eq!(value["result"]["cacheScope"], "private");
        assert!(value["result"].get("ttlMs").is_none());
    }

    #[test]
    fn discovery_and_error_envelopes_pass_through() {
        let filter = ToolFilter {
            allowed: AllowedTools::Set(HashSet::from(["search".to_owned()])),
            require_tools: false,
            schemas: None,
        };
        let discover = br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{}}}"#;
        assert!(filter_tool_list(discover, &filter).is_some());

        let error = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unknown"}}"#;
        assert!(filter_tool_list(error, &filter).is_some());
    }

    #[test]
    fn a_batch_filters_every_tool_list_element() {
        let filter = ToolFilter {
            allowed: AllowedTools::Set(HashSet::from(["search".to_owned()])),
            require_tools: true,
            schemas: None,
        };
        let body = json!([
            {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search"},{"name":"delete"}]}},
            {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"delete"}]}}
        ])
        .to_string()
        .into_bytes();

        let filtered = filter_tool_list(&body, &filter).expect("filtered");
        let value: Value = serde_json::from_slice(&filtered).unwrap();
        let responses = value.as_array().unwrap();

        assert_eq!(
            responses[0]["result"]["tools"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            responses[1]["result"]["tools"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn leaves_unknown_response_shapes_alone() {
        let filter = ToolFilter {
            allowed: AllowedTools::Set(HashSet::new()),
            require_tools: true,
            schemas: None,
        };
        assert!(filter_tool_list(b"not json", &filter).is_none());
        assert!(filter_tool_list(br#"{"result":{"content":[]}}"#, &filter).is_none());
    }

    #[test]
    fn validates_names_and_empty_allow_lists() {
        let empty = ToolPolicy {
            mode: ToolMode::AllowList,
            roles: HashMap::new(),
        };
        assert!(empty.validate().is_err());

        let bad = policy(ToolMode::AllowList, &[("support", &["bad\nname"])]);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn denial_is_a_json_rpc_error() {
        let body = denial_body(Some(json!(7)), "not permitted");
        let value: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["id"], 7);
        assert_eq!(value["error"]["code"], -32000);
    }
}
