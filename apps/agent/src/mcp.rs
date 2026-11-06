//! A small Model Context Protocol server over stdio: newline-delimited
//! JSON-RPC messages. It offers only what other devices share with this agent;
//! every call goes through the same checks as any device on the network.
use anyhow::Result;
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// Versions this server speaks; it answers with the client's when it can.
const PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// A request larger than this is refused unread.
const MAX_MESSAGE: usize = 64 * 1024;

/// What the agent can reach: the Spaces other devices share with it.
pub trait Shared {
    async fn list(&mut self) -> Result<Value>;
    async fn browse(&mut self, space: String, folder: Vec<String>) -> Result<Value>;
    async fn read(&mut self, space: String, name: String) -> Result<Value>;
    /// Ask the network's owner for access, in the agent's own words.
    async fn ask(&mut self, text: String) -> Result<Value>;
}

fn tools() -> Value {
    json!([
        {
            "name": "list_shared",
            "description": "List the shared spaces other devices on this Genesis Mesh network share with this agent.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
        },
        {
            "name": "browse",
            "description": "List the files and folders in a shared space, optionally inside a folder.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "space": {"type": "string", "description": "The space ID from list_shared."},
                    "folder": {"type": "array", "items": {"type": "string"}, "description": "Folder names from the space's top, in order."}
                },
                "required": ["space"],
                "additionalProperties": false
            }
        },
        {
            "name": "read_file",
            "description": "Read one file from a shared space. Text comes back as text; other files as their size and SHA-256.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "space": {"type": "string", "description": "The space ID from list_shared."},
                    "name": {"type": "string", "description": "The file's name in the space, as browse lists it."}
                },
                "required": ["space", "name"],
                "additionalProperties": false
            }
        },
        {
            "name": "ask_for_access",
            "description": "Ask the network's owner for access: say what you need and why, in up to 280 characters. The owner answers on their device; anything they share appears in list_shared.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request": {"type": "string", "description": "What you need and why, for example: The 2025 tax receipts, to prepare the yearly summary."}
                },
                "required": ["request"],
                "additionalProperties": false
            }
        }
    ])
}

fn text(arguments: &Value, field: &str) -> Result<String> {
    arguments[field]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("Give `{field}` as text"))
}

async fn call(shared: &mut impl Shared, params: &Value) -> Value {
    let arguments = &params["arguments"];
    let outcome = match params["name"].as_str() {
        Some("list_shared") => shared.list().await,
        Some("browse") => match text(arguments, "space") {
            Ok(space) => {
                let folder = arguments["folder"]
                    .as_array()
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                shared.browse(space, folder).await
            }
            Err(error) => Err(error),
        },
        Some("read_file") => match (text(arguments, "space"), text(arguments, "name")) {
            (Ok(space), Ok(name)) => shared.read(space, name).await,
            (Err(error), _) | (_, Err(error)) => Err(error),
        },
        Some("ask_for_access") => match text(arguments, "request") {
            Ok(request) => shared.ask(request).await,
            Err(error) => Err(error),
        },
        _ => Err(anyhow::anyhow!("Unknown tool")),
    };
    match outcome {
        Ok(value) => json!({"content": [{"type": "text", "text": value.to_string()}]}),
        // A refusal is an answer the agent should read, not a protocol failure.
        Err(error) => {
            json!({"content": [{"type": "text", "text": error.to_string()}], "isError": true})
        }
    }
}

/// The reply to one message, or none for a notification.
pub async fn handle(shared: &mut impl Shared, message: &Value) -> Option<Value> {
    let id = message
        .get("id")
        .filter(|id| id.is_string() || id.is_number())?
        .clone();
    let params = &message["params"];
    let result = match message["method"].as_str() {
        Some("initialize") => {
            let asked = params["protocolVersion"].as_str();
            let version = PROTOCOLS
                .iter()
                .find(|known| Some(**known) == asked)
                .unwrap_or(&PROTOCOLS[0]);
            Ok(json!({
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "genesismesh-connect-agent", "version": env!("CARGO_PKG_VERSION")}
            }))
        }
        Some("ping") => Ok(json!({})),
        Some("tools/list") => Ok(json!({"tools": tools()})),
        Some("tools/call") => Ok(call(shared, params).await),
        _ => Err(json!({"code": -32601, "message": "Method not found"})),
    };
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
    })
}

/// Serve messages from `input` until it closes.
pub async fn serve(
    shared: &mut impl Shared,
    input: impl AsyncBufRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut lines = input.lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = if line.len() > MAX_MESSAGE {
            Some(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "Message too large"}}),
            )
        } else {
            match serde_json::from_str::<Value>(&line) {
                Ok(message) => handle(shared, &message).await,
                Err(_) => Some(
                    json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}}),
                ),
            }
        };
        if let Some(reply) = reply {
            output.write_all(reply.to_string().as_bytes()).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One space with one file, and a refusal for anything else.
    struct Fake {
        calls: Vec<String>,
    }
    impl Shared for Fake {
        async fn list(&mut self) -> Result<Value> {
            self.calls.push("list".into());
            Ok(json!([{"space": "s1", "name": "Taxes 2025", "shared_by": "Home PC"}]))
        }
        async fn browse(&mut self, space: String, folder: Vec<String>) -> Result<Value> {
            self.calls
                .push(format!("browse {space} {}", folder.join("/")));
            anyhow::ensure!(space == "s1", "This space is not shared with this agent");
            Ok(json!({"space": space, "folder": folder, "files": [{"name": "summary.txt"}]}))
        }
        async fn read(&mut self, space: String, name: String) -> Result<Value> {
            self.calls.push(format!("read {space} {name}"));
            anyhow::ensure!(space == "s1", "This space is not shared with this agent");
            Ok(json!({"name": name, "text": "Total: 42"}))
        }
        async fn ask(&mut self, text: String) -> Result<Value> {
            self.calls.push(format!("ask {text}"));
            Ok(json!({"sent": true}))
        }
    }
    fn fake() -> Fake {
        Fake { calls: vec![] }
    }
    async fn ask(shared: &mut Fake, message: Value) -> Value {
        handle(shared, &message).await.expect("a reply")
    }

    #[tokio::test]
    async fn initialize_lists_the_tools_and_answers_ping() {
        let mut shared = fake();
        let init = ask(&mut shared, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}})).await;
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert!(init["result"]["capabilities"]["tools"].is_object());
        let unknown = ask(&mut shared, json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}})).await;
        assert_eq!(unknown["result"]["protocolVersion"], PROTOCOLS[0]);
        let tools = ask(
            &mut shared,
            json!({"jsonrpc":"2.0","id":"t","method":"tools/list"}),
        )
        .await;
        let names: Vec<_> = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            ["list_shared", "browse", "read_file", "ask_for_access"]
        );
        assert_eq!(
            ask(&mut shared, json!({"jsonrpc":"2.0","id":3,"method":"ping"})).await["result"],
            json!({})
        );
        assert!(
            shared.calls.is_empty(),
            "Listing tools reaches nothing on the network"
        );
    }

    #[tokio::test]
    async fn tool_calls_reach_the_network_and_refusals_come_back_as_errors() {
        let mut shared = fake();
        let call = |name: &str, arguments: Value| json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":name,"arguments":arguments}});
        let listed = ask(&mut shared, call("list_shared", json!({}))).await;
        assert!(
            listed["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Taxes 2025")
        );
        let browsed = ask(
            &mut shared,
            call("browse", json!({"space":"s1","folder":["2025"]})),
        )
        .await;
        assert!(browsed["result"].get("isError").is_none());
        let read = ask(
            &mut shared,
            call("read_file", json!({"space":"s1","name":"summary.txt"})),
        )
        .await;
        assert!(
            read["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Total: 42")
        );
        let refused = ask(
            &mut shared,
            call("read_file", json!({"space":"other","name":"secret.txt"})),
        )
        .await;
        assert_eq!(refused["result"]["isError"], true);
        assert!(
            refused["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("not shared")
        );
        let missing = ask(&mut shared, call("read_file", json!({"space":"s1"}))).await;
        assert_eq!(missing["result"]["isError"], true);
        let unknown = ask(&mut shared, call("delete_file", json!({}))).await;
        assert_eq!(unknown["result"]["isError"], true);
        let asked = ask(
            &mut shared,
            call(
                "ask_for_access",
                json!({"request":"The 2025 receipts, for the summary"}),
            ),
        )
        .await;
        assert!(asked["result"].get("isError").is_none());
        let empty = ask(&mut shared, call("ask_for_access", json!({"request":""}))).await;
        assert_eq!(empty["result"]["isError"], true);
        assert_eq!(
            shared.calls,
            [
                "list",
                "browse s1 2025",
                "read s1 summary.txt",
                "read other secret.txt",
                "ask The 2025 receipts, for the summary"
            ]
        );
    }

    #[tokio::test]
    async fn notifications_get_no_reply_and_unknown_methods_an_error() {
        let mut shared = fake();
        assert!(
            handle(
                &mut shared,
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"})
            )
            .await
            .is_none()
        );
        let unknown = ask(
            &mut shared,
            json!({"jsonrpc":"2.0","id":4,"method":"resources/list"}),
        )
        .await;
        assert_eq!(unknown["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn serve_answers_line_by_line_and_rejects_malformed_or_oversized_input() {
        let mut shared = fake();
        let input = format!(
            "{}\nnot json\n{}\n\n{}\n",
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            "x".repeat(MAX_MESSAGE + 1),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        );
        let mut output = Vec::new();
        serve(&mut shared, input.as_bytes(), &mut output)
            .await
            .unwrap();
        let replies: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0]["result"], json!({}));
        assert_eq!(replies[1]["error"]["code"], -32700);
        assert_eq!(replies[2]["error"]["code"], -32600);
    }
}
