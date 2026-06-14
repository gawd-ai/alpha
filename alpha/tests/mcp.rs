//! The alpha-mcp control-hub, driven over its real stdio pipes.
//!
//! The hub **is** a sanctum: there is no separate daemon and no HTTP. We spawn `alpha mcp` (a
//! headless node whose `surface-mcp` creature owns stdio) and drive it over newline-delimited JSON-RPC
//! 2.0 — each tool call becomes a `Verb` envelope on the node's own bus. The
//! cases cover the handshake / tool catalog / error taxonomy / the allow-AI gate over the bus, and a
//! full self-contained co-drive (author a critter on the hub's own node, then message it).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

/// Drives the alpha-mcp control-hub over stdio (newline-delimited JSON-RPC 2.0).
struct Mcp {
    child: Child,
    stdin: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Mcp {
    /// Spawn the hub with the given CLI args (e.g. `--allow-ai`). No env, no external daemon — the
    /// hub boots its own node.
    fn spawn(args: &[&str]) -> Mcp {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_alpha"));
        cmd.arg("mcp");
        cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = cmd.spawn().expect("spawn alpha mcp");
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Mcp { child, stdin, out }
    }

    fn send(&mut self, msg: Value) {
        let mut s = serde_json::to_string(&msg).unwrap();
        s.push('\n');
        self.stdin.write_all(s.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        let n = self.out.read_line(&mut line).expect("read line");
        assert!(n > 0, "alpha-mcp closed stdout before replying");
        serde_json::from_str(line.trim())
            .unwrap_or_else(|e| panic!("bad JSON-RPC line ({e}): {line:?}"))
    }

    fn handshake(&mut self) -> Value {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "alpha-mcp-test", "version": "0.0.0" }
            }
        }));
        let resp = self.recv();
        self.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        resp
    }

    fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.send(json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": args }
        }));
        self.recv()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The text payload of a tool result, parsed as JSON (the surface wraps `VerbResult.json` as text).
fn content_json(resp: &Value) -> Value {
    let text = resp["result"]["content"][0]["text"].as_str().expect("content text");
    serde_json::from_str(text).expect("content text is JSON")
}

#[test]
fn handshake_tools_list_and_unknown_method() {
    let mut mcp = Mcp::spawn(&["--minimal"]); // bare control plane is enough for the catalog

    let init = mcp.handshake();
    assert_eq!(init["result"]["protocolVersion"], json!("2025-11-25"));
    assert_eq!(init["result"]["serverInfo"]["name"], json!("alpha-mcp"));

    mcp.send(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    let list = mcp.recv();
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 19, "the tool catalog has 19 entries");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "alpha_status",
        "alpha_journal",
        "alpha_author_critter",
        "alpha_send",
        "alpha_ai_status",
        "alpha_cluster",
        "alpha_cluster_connect",
        "alpha_registry_publish",
        "alpha_registry_fetch",
        "alpha_registry_list",
        "alpha_registry_fetch_load",
        "alpha_bestiary_prove",
    ] {
        assert!(names.contains(&expected), "tool `{expected}` is in the catalog: {names:?}");
    }
    let status_tool = tools.iter().find(|t| t["name"] == json!("alpha_status")).unwrap();
    assert_eq!(status_tool["annotations"]["readOnlyHint"], json!(true), "read tool is annotated");
    // The new registry/bestiary reads carry readOnlyHint; publish (a mutation) does not.
    let prove_tool = tools.iter().find(|t| t["name"] == json!("alpha_bestiary_prove")).unwrap();
    assert_eq!(
        prove_tool["annotations"]["readOnlyHint"],
        json!(true),
        "bestiary prove is read-only"
    );
    let publish_tool = tools.iter().find(|t| t["name"] == json!("alpha_registry_publish")).unwrap();
    assert_ne!(
        publish_tool["annotations"]["readOnlyHint"],
        json!(true),
        "registry publish is a mutation, not read-only"
    );
    // fetch-load loads code into the node → a mutation, gated, not read-only.
    let fetch_load_tool =
        tools.iter().find(|t| t["name"] == json!("alpha_registry_fetch_load")).unwrap();
    assert_ne!(
        fetch_load_tool["annotations"]["readOnlyHint"],
        json!(true),
        "registry fetch-load loads code, so it is a mutation, not read-only"
    );

    mcp.send(json!({ "jsonrpc": "2.0", "id": 3, "method": "frobnicate" }));
    let err = mcp.recv();
    assert_eq!(err["error"]["code"], json!(-32601), "unknown method → method-not-found");
}

#[test]
fn reads_succeed_but_mutations_are_gated_over_the_bus() {
    // The hub is its own node. With allow-ai OFF (default), a read answers against the hub's own
    // node, but a mutating verb is refused by the allow-AI gate — proving the gate holds over the
    // MCP→bus path, not just over HTTP.
    let mut mcp = Mcp::spawn(&[]);
    mcp.handshake();

    let status = mcp.call(2, "alpha_status", json!({}));
    assert_ne!(
        status["result"]["isError"],
        json!(true),
        "a read succeeds on the hub's node: {status}"
    );
    let j = content_json(&status);
    assert_eq!(j["ai_allowed"], json!(false), "allow-ai is off by default");

    let authored = mcp.call(3, "alpha_author_critter", json!({ "request": "uppercase" }));
    assert_eq!(
        authored["result"]["isError"],
        json!(true),
        "a mutation is gated while allow-ai is off"
    );
    let err = content_json(&authored);
    assert_eq!(err["error"], json!("ai-not-allowed"), "refusal is the allow-ai gate: {err}");
}

#[test]
fn malformed_tool_arguments_are_rejected_before_reaching_the_node() {
    let mut mcp = Mcp::spawn(&["--minimal"]);
    mcp.handshake();

    let bad_id = mcp.call(2, "alpha_send", json!({ "id": "not-a-number", "text": "hi" }));
    assert_eq!(bad_id["result"]["isError"], json!(true));
    let text = bad_id["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("parameter `id`") && text.contains("non-negative integer"),
        "bad id should be rejected locally, not coerced to zero: {text}"
    );

    let bad_bool = mcp.call(3, "alpha_ai_status", json!({ "working": "yes" }));
    assert_eq!(bad_bool["result"]["isError"], json!(true));
    let text = bad_bool["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("parameter `working`") && text.contains("boolean"),
        "bad boolean should be rejected locally, not coerced to false: {text}"
    );

    let extra = mcp.call(4, "alpha_status", json!({ "surprise": true }));
    assert_eq!(extra["result"]["isError"], json!(true));
    let text = extra["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("unknown parameter `surprise`"), "extra fields are rejected: {text}");
}

#[test]
fn end_to_end_author_critter_then_send_on_the_hubs_own_node() {
    // No separate daemon: the hub authors a reverse critter on its OWN node and messages it — every
    // hop is a Verb envelope on the bus. `--allow-ai` opens the gate on the hub's node.
    let mut mcp = Mcp::spawn(&["--allow-ai"]);
    mcp.handshake();

    let authored = mcp.call(2, "alpha_author_critter", json!({ "request": "reverse the bytes" }));
    assert_ne!(authored["result"]["isError"], json!(true), "author should succeed: {authored}");
    let id = content_json(&authored)["creature_id"].as_u64().expect("creature_id in author result");

    let sent = mcp.call(3, "alpha_send", json!({ "id": id, "text": "hello" }));
    assert_eq!(content_json(&sent)["reply"], json!("olleh"), "the reverse critter replies olleh");
}
