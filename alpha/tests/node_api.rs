//! The alpha node HTTP control plane: Bearer auth, the allow-AI gate,
//! and the human/AI co-drive path. Spawns the real `alpha node` binary with `--listen … --headless` and
//! drives it over raw HTTP/1.1 (no HTTP client dep in the test).
//!
//! Each test asks the OS for an ephemeral loopback port before spawning its daemon, so public test
//! runs do not depend on a fixed local port being free.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// A spawned alpha node daemon; killed on drop.
struct Daemon {
    child: Child,
    port: u16,
}

impl Daemon {
    fn spawn(port: u16, minimal: bool, allow_ai: bool) -> Daemon {
        Self::spawn_with_env_key(port, minimal, allow_ai, None)
    }

    fn spawn_with_env_key(
        port: u16,
        minimal: bool,
        allow_ai: bool,
        env_key: Option<&str>,
    ) -> Daemon {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_alpha"));
        cmd.arg("node");
        cmd.args(["--listen", &format!("127.0.0.1:{port}"), "--headless"]);
        if let Some(key) = env_key {
            cmd.env("SANCTUM_API_KEY", key);
        } else {
            cmd.args(["--api-key", "testkey"]);
        }
        if minimal {
            cmd.arg("--minimal");
        }
        if allow_ai {
            cmd.arg("--allow-ai");
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn alpha node");
        let d = Daemon { child, port };
        d.wait_ready();
        d
    }

    /// Poll until the API actually answers — a real `GET /api/health` 200, not just a TCP connect
    /// (the listener can be bound, with connects queuing in the backlog, before axum is accepting).
    fn wait_ready(&self) {
        for _ in 0..200 {
            if health_ok(self.port) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("alpha node API did not answer /api/health on port {}", self.port);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve ephemeral loopback port")
        .local_addr()
        .expect("reserved listener has a local address")
        .port()
}

/// A non-panicking `GET /api/health` probe used for readiness: true iff the API answered 200.
fn health_ok(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let req = "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let _ = stream.flush();
    let mut resp = String::new();
    if stream.read_to_string(&mut resp).is_err() {
        return false;
    }
    resp.split_whitespace().nth(1) == Some("200")
}

/// One raw HTTP/1.1 request → `(status_code, body)`. `Connection: close` so the read terminates.
fn http(
    port: u16,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let payload = body.unwrap_or("");
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if let Some(k) = key {
        req.push_str(&format!("Authorization: Bearer {k}\r\n"));
    }
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req.push_str("\r\n");
    req.push_str(payload);
    stream.write_all(req.as_bytes()).expect("write request");
    stream.flush().ok();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    let status = resp.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    let body = resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("").to_string();
    (status, body)
}

/// Extract the JSON object from a response body (robust to any HTTP framing around it).
fn json_of(body: &str) -> serde_json::Value {
    match (body.find('{'), body.rfind('}')) {
        (Some(s), Some(e)) if e >= s => {
            serde_json::from_str(&body[s..=e]).unwrap_or(serde_json::Value::Null)
        }
        _ => serde_json::Value::Null,
    }
}

#[test]
fn health_is_public_auth_required_and_gate_blocks_mutation() {
    // No --allow-ai: the gate is closed. --minimal is enough — the gate refuses before any organ work.
    let d = Daemon::spawn(free_port(), true, false);

    // /api/health needs no auth.
    let (sc, body) = http(d.port, "GET", "/api/health", None, None);
    assert_eq!(sc, 200, "health is public");
    assert_eq!(json_of(&body)["ok"], serde_json::json!(true));

    // A protected route without a Bearer key → 401.
    let (sc, _) = http(d.port, "GET", "/api/status", None, None);
    assert_eq!(sc, 401, "protected route needs a Bearer key");

    // With the key → 200, and allow-ai is off by default.
    let (sc, body) = http(d.port, "GET", "/api/status", Some("testkey"), None);
    assert_eq!(sc, 200);
    assert_eq!(json_of(&body)["ai_allowed"], serde_json::json!(false));

    // A mutating verb is gated while allow-ai is off → 403 ai-not-allowed (read-only worked above).
    let (sc, body) = http(
        d.port,
        "POST",
        "/api/author/critter",
        Some("testkey"),
        Some(r#"{"request":"reverse the bytes"}"#),
    );
    assert_eq!(sc, 403, "gated mutation refused while allow-ai is off: {body}");
    assert_eq!(json_of(&body)["error"], serde_json::json!("ai-not-allowed"));
}

#[test]
fn api_key_can_come_from_environment() {
    let d = Daemon::spawn_with_env_key(free_port(), true, false, Some("env-test-key"));

    let (sc, _) = http(d.port, "GET", "/api/status", Some("wrong"), None);
    assert_eq!(sc, 401, "wrong Bearer key must not be accepted");

    let (sc, body) = http(d.port, "GET", "/api/status", Some("env-test-key"), None);
    assert_eq!(sc, 200, "SANCTUM_API_KEY should be honored: {body}");
    assert_eq!(json_of(&body)["ai_allowed"], serde_json::json!(false));
}

#[test]
fn send_to_missing_creature_is_a_route_error_not_a_successful_timeout() {
    let d = Daemon::spawn(free_port(), true, true);

    let (sc, body) =
        http(d.port, "POST", "/api/send", Some("testkey"), Some(r#"{"id":999999,"text":"hello"}"#));
    assert_eq!(sc, 400, "missing creature should be a client-visible route error: {body}");
    let j = json_of(&body);
    assert_eq!(j["unrouted"], serde_json::json!(true), "route failure is explicit: {body}");
    assert!(
        j["error"].as_str().unwrap_or("").contains("no such creature"),
        "router error is preserved: {body}"
    );
    assert_ne!(
        j["timeout"],
        serde_json::json!(true),
        "route failure must not masquerade as a timeout"
    );
}

#[test]
fn oversized_http_json_body_is_rejected_at_the_surface() {
    let d = Daemon::spawn(free_port(), true, true);
    let oversized = format!(r#"{{"request":"{}"}}"#, "x".repeat(1024 * 1024 + 1));

    let (sc, body) = http(d.port, "POST", "/api/author/critter", Some("testkey"), Some(&oversized));
    assert_eq!(sc, 413, "oversized JSON body should be rejected before control: {body}");
}

#[test]
fn oversized_http_field_is_rejected_before_control_dispatch() {
    let d = Daemon::spawn(free_port(), true, true);
    let body =
        format!(r#"{{"manifest_path":"{}","artifact_path":"artifact.so"}}"#, "x".repeat(4097));

    let (sc, body) = http(d.port, "POST", "/api/load", Some("testkey"), Some(&body));

    assert_eq!(sc, 400, "oversized field should be rejected at the surface: {body}");
    let j = json_of(&body);
    assert_eq!(j["error"], serde_json::json!("bad-http-argument"));
    assert_eq!(j["field"], serde_json::json!("manifest_path"));
    assert_eq!(j["limit"], serde_json::json!(4096));
}

/// The surface refuses an authoring request at the AUTHORING contract's own field cap — the limit
/// the bindees' `decode_authoring_request` would apply anyway. A request that passes the front
/// door never fails the same size check deeper in the pipeline (and the advertised limit is the
/// enforced one, not the looser generic text cap).
#[test]
fn oversized_author_request_is_rejected_at_the_surface_with_the_contract_cap() {
    let d = Daemon::spawn(free_port(), true, true);
    let cap = omni::MAX_CONTROL_AUTHOR_REQUEST_BYTES;
    let body = format!(r#"{{"request":"{}"}}"#, "x".repeat(cap + 1));

    let (sc, body) = http(d.port, "POST", "/api/author/critter", Some("testkey"), Some(&body));

    assert_eq!(sc, 400, "over-cap author request should be rejected at the surface: {body}");
    let j = json_of(&body);
    assert_eq!(j["error"], serde_json::json!("bad-http-argument"));
    assert_eq!(j["field"], serde_json::json!("request"));
    assert_eq!(j["limit"], serde_json::json!(cap));
}

#[test]
fn co_drive_author_critter_then_send_over_the_api() {
    // --allow-ai opens the gate; full boot wires AUTHORING + build-critter so authoring really runs.
    let d = Daemon::spawn(free_port(), false, true);

    let (sc, body) = http(
        d.port,
        "POST",
        "/api/author/critter",
        Some("testkey"),
        Some(r#"{"request":"reverse the bytes"}"#),
    );
    assert_eq!(sc, 200, "author critter should succeed when allow-ai is on: {body}");
    let j = json_of(&body);
    assert_eq!(j["ok"], serde_json::json!(true), "author result: {body}");
    let id = j["creature_id"].as_u64().expect("creature_id in the author response");

    // Send to the authored reverse critter and read its reply.
    let send = format!(r#"{{"id":{id},"text":"hello"}}"#);
    let (sc, body) = http(d.port, "POST", "/api/send", Some("testkey"), Some(&send));
    assert_eq!(sc, 200, "send should succeed: {body}");
    assert_eq!(
        json_of(&body)["reply"],
        serde_json::json!("olleh"),
        "the reverse critter replies olleh"
    );
}

#[test]
fn http_route_set_is_the_mcp_verb_set_minus_watch() {
    // TRD-003 R1, HTTP column of the verb×surface parity matrix. The HTTP surface exposes exactly the
    // MCP `alpha_*` verbs MINUS `alpha_watch` (no `/api/watch` — streaming lives on `/api/ws`), plus
    // the public health/ws routes. A wired path answers non-404 even unauthenticated (401) or on the
    // wrong method (405); an unregistered path answers 404. So `non-404 ⟺ the route exists`, which lets
    // us pin the set behaviourally against the real running router (no axum route introspection).
    let d = Daemon::spawn(free_port(), true, false); // --minimal: routes exist regardless of organs

    // The 26 verb routes = the 27 MCP tools minus `alpha_watch`. Mirrors `surface-http::router()` and
    // the TRD-003 matrix; if a verb is added to one surface but not the other, this breaks.
    let verb_routes = [
        "/api/status",
        "/api/creatures",
        "/api/journal",
        "/api/author",
        "/api/author/critter",
        "/api/load",
        "/api/registry/publish",
        "/api/registry/fetch",
        "/api/registry/list",
        "/api/registry/fetch-load",
        "/api/bestiary/prove",
        "/api/functions/resolve",
        "/api/functions/deploy",
        "/api/functions/undeploy",
        "/api/functions/deployments",
        "/api/jobs/submit",
        "/api/jobs/get",
        "/api/jobs/events",
        "/api/jobs/control",
        "/api/send",
        "/api/intent",
        "/api/bind",
        "/api/unload",
        "/api/ai/status",
        "/api/cluster",
        "/api/cluster/connect",
    ];
    assert_eq!(verb_routes.len(), 26, "the 27 MCP tools minus alpha_watch");
    for path in verb_routes {
        let (sc, _) = http(d.port, "GET", path, None, None);
        assert_ne!(sc, 404, "`{path}` must be a wired HTTP route (got 404)");
    }

    // The deliberate asymmetry: `alpha_watch` has NO HTTP route by design (use `/api/ws`).
    let (sc, _) = http(d.port, "GET", "/api/watch", None, None);
    assert_eq!(sc, 404, "alpha_watch has no /api/watch route by design (streaming is /api/ws)");

    // Publics, and a control: an unknown path is 404, proving 404 here means "no route".
    assert_eq!(http(d.port, "GET", "/api/health", None, None).0, 200, "health is public");
    assert_ne!(
        http(d.port, "GET", "/api/ws", None, None).0,
        404,
        "/api/ws is a wired public route"
    );
    assert_eq!(
        http(d.port, "GET", "/api/no-such-route", None, None).0,
        404,
        "an unregistered path is 404 (control for the non-404 ⟺ exists assumption)"
    );
}
