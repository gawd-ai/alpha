//! Prompt assembly + response parsing for the model-backed author.
//!
//! The response contract is **two fenced blocks** — a source block (```rust for a daemon, ```rhai
//! for a critter) and a ```json manifest-stub block. This is robust against JSON-escaping a whole
//! source file into one string field. Parsing **fails closed**: a missing source block, a
//! missing/malformed json stub, or a source that doesn't carry the tier's required entrypoint, is a
//! structured [`AuthoringError::Invalid`] — never a synthesized permissive default (a defaulted
//! `ManifestStub` carries `net: None` + empty `provides`, a silent capability mis-declaration for a
//! native trusted-by-admission creature).

use agent_templated::{AuthoringError, AuthoringRequest, AuthoringResponse};
use build_cargo::ManifestStub;
use mind::{Prompt, RETRY_MARKER};

/// Which creature tier the request asks for. Mirrors `agent-templated`'s keyword routing: a request
/// mentioning "critter" authors the sandboxed script tier; everything else is a native daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Daemon,
    Critter,
}

/// Decide the tier from the request text (the control plane appends "critter" for `author --critter`).
pub fn tier_of(req: &AuthoringRequest) -> Tier {
    if req.request.to_ascii_lowercase().contains("critter") {
        Tier::Critter
    } else {
        Tier::Daemon
    }
}

/// System prompt for the native daemon tier: a single-file `forge` creature ending in
/// `declare_creature!`, std + forge only (the two-block contract has no slot for extra deps).
const DAEMON_SYSTEM_PROMPT: &str = r#"You are an authoring creature for the Alpha substrate (the GAWD fabric).
You receive a natural-language outcome and must produce ONE self-contained Rust source file for a
`forge` creature, plus a manifest stub.

Hard requirements for the Rust source:
- Start with `use forge::prelude::*;`.
- Define one public type that derives `Default` and `impl Creature for` it.
- Implement `fn bind(&mut self, _ctx: CreatureCtx) {}` and `fn handle(&mut self, env: Envelope) -> Outcome`.
- The creature's only output is the envelopes it returns from `handle` (reply with `Outcome::reply(&env, bytes)`).
- End the file with `forge::declare_creature!(YourType);`.
- Use only the standard library and `forge` (no external crates).

Respond with EXACTLY two fenced code blocks and nothing that must be parsed outside them:
1. A ```rust block containing the full source file.
2. A ```json block containing the manifest stub: an object with "name", "version", "entrypoints"
   (each {"name","signature"}), optional "capabilities", and "provides" (array). Declare any
   outbound network or filesystem capability the creature actually needs — under-declaring is a
   capability mis-declaration the admission policy may reject.

Worked example for "reverse a string":

```rust
use forge::prelude::*;

#[derive(Default)]
pub struct ReverseDaemon;

impl Creature for ReverseDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }
}

forge::declare_creature!(ReverseDaemon);
```

```json
{ "name": "reverse-daemon", "version": "0.1.0", "entrypoints": [{ "name": "handle", "signature": "(Envelope) -> Outcome" }], "provides": [] }
```
"#;

// The critter system prompt embeds CRITTER-TIER (the marker the fake backend keys on); keep it in
// the text so a swap to a real model is a no-op and the fake answers in the right tier.
const CRITTER_SYSTEM_PROMPT: &str = r#"You are an authoring creature for the Alpha substrate (the GAWD fabric).
Author a CRITTER-TIER creature: a single sandboxed Rhai script (the script tier), NOT Rust.

Hard requirements for the Rhai source:
- Define `fn handle(env) { ... }`. `env.payload` is a blob of the inbound bytes.
- Build the reply with `let out = blob();` then `out.push(byte);`, and return `out` as the last expression.
- No `import`, no `eval`, no host calls — a critter reaches nothing but its own script.
- Do NOT use `declare_creature!` (that is the native-tier macro); a critter is just the script.

Respond with EXACTLY two fenced code blocks and nothing else:
1. A ```rhai block containing the full Rhai script.
2. A ```json block with the manifest stub: "name", "version", "entrypoints" ({"name","signature"}),
   and "provides" (array).

Worked example for "reverse the bytes":

```rhai
fn handle(env) {
    let src = env.payload;
    let out = blob();
    let i = src.len();
    while i > 0 {
        i -= 1;
        out.push(src[i]);
    }
    out
}
```

```json
{ "name": "reverse-critter", "version": "0.1.0", "entrypoints": [{ "name": "handle", "signature": "(env) -> reply" }], "provides": [] }
```
"#;

/// Assemble the model request from an [`AuthoringRequest`]. The system prompt is tier-specific; on a
/// retry the structured compiler `prev_error` is appended under [`RETRY_MARKER`] so the model can fix
/// the previous attempt.
pub fn build_request(req: &AuthoringRequest) -> Prompt {
    let system_prompt = match tier_of(req) {
        Tier::Daemon => DAEMON_SYSTEM_PROMPT,
        Tier::Critter => CRITTER_SYSTEM_PROMPT,
    }
    .to_string();
    let mut user_prompt = req.request.clone();
    if let Some(prev) = &req.prev_error {
        user_prompt.push_str(&format!(
            "\n\n{RETRY_MARKER} (your previous attempt failed to compile — read the error and fix it):\n{prev}"
        ));
    }
    Prompt { system_prompt, user_prompt, max_tokens: 4096, temperature: 0.2 }
}

/// Parse a model completion into an [`AuthoringResponse`] for `tier`. Fails closed (see module docs).
pub fn parse_response(tier: Tier, content: &str) -> Result<AuthoringResponse, AuthoringError> {
    let (source_langs, required, template): (&[&str], &str, &str) = match tier {
        // A daemon must end in `declare_creature!`; a critter must define `fn handle`. The required
        // token is the fail-loud backstop against a truncated/partial model response.
        Tier::Daemon => (&["rust", "rs"], "declare_creature!", "agent-mind"),
        Tier::Critter => (&["rhai", "rust", "rs"], "fn handle", "agent-mind-critter"),
    };
    let source = extract_fenced(content, source_langs).ok_or_else(|| AuthoringError::Invalid {
        message: format!("model response contained no {source_langs:?} source block"),
    })?;
    if !source.contains(required) {
        return Err(AuthoringError::Invalid {
            message: format!(
                "authored source is missing the required `{required}` — it looks truncated or incomplete (fail-closed)"
            ),
        });
    }
    let stub_json = extract_fenced(content, &["json"]).ok_or_else(|| AuthoringError::Invalid {
        message: "model response contained no ```json manifest stub block (fail-closed)"
            .to_string(),
    })?;
    let mut manifest_stub: ManifestStub =
        serde_json::from_str(stub_json.trim()).map_err(|e| AuthoringError::Invalid {
            message: format!("malformed manifest stub JSON (fail-closed): {e}"),
        })?;
    if manifest_stub.name.trim().is_empty() {
        return Err(AuthoringError::Invalid {
            message: "manifest stub has an empty name (fail-closed)".to_string(),
        });
    }
    if manifest_stub.version.trim().is_empty() {
        manifest_stub.version = "0.1.0".to_string();
    }
    let mut source = source.trim_end().to_string();
    source.push('\n');
    Ok(AuthoringResponse {
        crate_name: manifest_stub.name.clone(),
        crate_version: manifest_stub.version.clone(),
        source,
        manifest_stub,
        deps: vec![],
        template: template.to_string(),
    })
}

/// Extract the body of the first fenced code block whose info string matches one of `langs`
/// (case-insensitive). **Line-oriented**: only a line whose first non-whitespace is ``` opens or
/// closes a fence, so an inner ` ``` ` *inside* a block (e.g. a `/// ```` rustdoc example in the
/// authored source) does NOT desync the scanner — the previous byte-`find` approach truncated valid
/// source at the first such inner fence. Scans every block so order (rust-then-json or json-first)
/// doesn't matter.
fn extract_fenced(content: &str, langs: &[&str]) -> Option<String> {
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let Some(info) = trimmed.strip_prefix("```") else { continue };
        // Opener: the info string is the rest of this line (the language tag).
        let is_match = langs.iter().any(|l| info.trim().eq_ignore_ascii_case(l));
        let mut body = String::new();
        let mut closed = false;
        for inner in lines.by_ref() {
            if inner.trim_start().starts_with("```") {
                closed = true;
                break;
            }
            body.push_str(inner);
            body.push('\n');
        }
        if !closed {
            // Unterminated fence — give up rather than return a half block.
            return None;
        }
        if is_match {
            return Some(body);
        }
        // Not our language: keep scanning after this block's close (the inner loop consumed it).
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use mind::CRITTER_TIER_MARKER;

    #[test]
    fn tier_of_routes_on_the_critter_keyword() {
        assert_eq!(
            tier_of(&AuthoringRequest { request: "reverse a string".into(), ..Default::default() }),
            Tier::Daemon
        );
        assert_eq!(
            tier_of(&AuthoringRequest {
                request: "reverse it critter".into(),
                ..Default::default()
            }),
            Tier::Critter
        );
    }

    #[test]
    fn critter_prompt_carries_the_tier_marker() {
        let r = build_request(&AuthoringRequest {
            request: "reverse critter".into(),
            ..Default::default()
        });
        assert!(r.system_prompt.contains(CRITTER_TIER_MARKER), "critter prompt marks the tier");
        let d =
            build_request(&AuthoringRequest { request: "reverse".into(), ..Default::default() });
        assert!(!d.system_prompt.contains(CRITTER_TIER_MARKER), "daemon prompt does not");
    }

    #[test]
    fn build_request_appends_prev_error_under_the_retry_marker() {
        let base = build_request(&AuthoringRequest { request: "reverse".into(), prev_error: None });
        assert!(!base.user_prompt.contains(RETRY_MARKER), "no marker without prev_error");
        let retry = build_request(&AuthoringRequest {
            request: "reverse".into(),
            prev_error: Some("error[E0601]: expected item".into()),
        });
        assert!(retry.user_prompt.contains(RETRY_MARKER));
        assert!(retry.user_prompt.contains("E0601"));
    }

    #[test]
    fn extract_fenced_ignores_inner_rustdoc_fences() {
        // The exact desync the line-oriented scanner fixes: a rustdoc ``` fence inside the source.
        let content = "\
```rust
use forge::prelude::*;
/// # Example
/// ```
/// let x = 1;
/// ```
pub struct D;
forge::declare_creature!(D);
```
```json
{\"name\":\"d\",\"version\":\"0.1.0\"}
```";
        let r = parse_response(Tier::Daemon, content).unwrap();
        assert!(r.source.contains("declare_creature!"), "full source survives inner fences");
        assert!(r.source.contains("pub struct D"));
        assert_eq!(r.crate_name, "d");
    }

    #[test]
    fn parse_response_extracts_both_blocks_in_either_order() {
        let rust_first =
            "```rust\nforge::declare_creature!(X);\n```\n```json\n{\"name\":\"x\",\"version\":\"0.1.0\"}\n```";
        let r = parse_response(Tier::Daemon, rust_first).unwrap();
        assert_eq!(r.crate_name, "x");

        let json_first =
            "```json\n{\"name\":\"y\",\"version\":\"0.2.0\"}\n```\n```rust\nforge::declare_creature!(Y);\n```";
        let r = parse_response(Tier::Daemon, json_first).unwrap();
        assert_eq!(r.crate_name, "y");
        assert_eq!(r.crate_version, "0.2.0");
    }

    #[test]
    fn parse_response_critter_accepts_rhai_and_requires_fn_handle() {
        let ok = "```rhai\nfn handle(env) { env.payload }\n```\n```json\n{\"name\":\"c\",\"version\":\"0.1.0\"}\n```";
        let r = parse_response(Tier::Critter, ok).unwrap();
        assert_eq!(r.template, "agent-mind-critter");
        assert_eq!(r.crate_name, "c");

        let no_handle =
            "```rhai\nfn nope() {}\n```\n```json\n{\"name\":\"c\",\"version\":\"0.1.0\"}\n```";
        assert!(matches!(
            parse_response(Tier::Critter, no_handle),
            Err(AuthoringError::Invalid { .. })
        ));
    }

    #[test]
    fn parse_response_fails_closed_on_missing_source_block() {
        let e =
            parse_response(Tier::Daemon, "```json\n{\"name\":\"x\",\"version\":\"0.1.0\"}\n```")
                .unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "got {e:?}");
    }

    #[test]
    fn parse_response_fails_closed_on_missing_json_stub() {
        let e =
            parse_response(Tier::Daemon, "```rust\nforge::declare_creature!(X);\n```").unwrap_err();
        match e {
            AuthoringError::Invalid { message } => assert!(message.contains("fail-closed")),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_fails_closed_on_truncated_source_missing_macro() {
        // A rust block that lacks declare_creature! (e.g. truncated) is rejected, not passed to build.
        let e = parse_response(Tier::Daemon, "```rust\nuse forge::prelude::*;\n```\n```json\n{\"name\":\"x\",\"version\":\"0.1.0\"}\n```").unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "got {e:?}");
    }

    #[test]
    fn parse_response_fails_closed_on_malformed_json_stub() {
        let e = parse_response(
            Tier::Daemon,
            "```rust\nforge::declare_creature!(X);\n```\n```json\n{ not json\n```",
        )
        .unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "got {e:?}");
    }

    #[test]
    fn parse_response_defaults_empty_version_but_rejects_empty_name() {
        let r = parse_response(
            Tier::Daemon,
            "```rust\nforge::declare_creature!(Z);\n```\n```json\n{\"name\":\"z\",\"version\":\"\"}\n```",
        )
        .unwrap();
        assert_eq!(r.crate_version, "0.1.0", "empty version defaults");
        let e = parse_response(
            Tier::Daemon,
            "```rust\nforge::declare_creature!(X);\n```\n```json\n{\"name\":\"\",\"version\":\"1\"}\n```",
        )
        .unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "empty name fails closed: {e:?}");
    }
}
