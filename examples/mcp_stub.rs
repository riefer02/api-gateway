//! Minimal MCP upstream for local demos and tests.
//!
//! It is intentionally not a real MCP implementation: it answers
//! `tools/list`, `tools/call`, and `server/discover` well enough to exercise
//! the gateway's policy, audit, and timing paths. No authentication.

use axum::{Json, Router, routing::post};
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("MCP_STUB_PORT").unwrap_or_else(|_| "18100".to_owned());

    let app = Router::new().route("/mcp", post(handle));

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;
    eprintln!("MCP stub listening on http://127.0.0.1:{port}/mcp");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle(Json(body): Json<Value>) -> Json<Value> {
    if let Some(batch) = body.as_array() {
        let answers: Vec<Value> = batch.iter().map(answer).collect();

        return Json(Value::Array(answers));
    }

    Json(answer(&body))
}

fn answer(request: &Value) -> Value {
    let id = request
        .get("id")
        .cloned()
        .unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2026-07-28",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "mcp-stub", "version": "0.1.0" }
        }),
        "server/discover" => json!({
            "protocolVersion": "2026-07-28",
            "capabilities": { "tools": {} }
        }),
        "tools/list" => json!({
            "tools": [
                {
                    "name": "search_tickets",
                    "description": "Search the demo ticket store",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "query": { "type": "string" } }
                    }
                },
                {
                    "name": "delete_ticket",
                    "description": "Delete a demo ticket (write)",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "id": { "type": "string" } }
                    }
                }
            ]
        }),
        "tools/call" => {
            let tool = request
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");

            json!({
                "content": [{ "type": "text", "text": format!("stub executed `{tool}`") }],
                "isError": false
            })
        }
        _ => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("unknown method `{method}`") }
            });
        }
    };

    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}
