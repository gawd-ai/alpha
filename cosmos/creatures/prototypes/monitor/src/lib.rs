//! `monitor` — a reference injected creature (NOT substrate): the substrate's *nervous-system view*.
//!
//! The kernel publishes a creature's liveness on [`Topic::PROPRIOCEPTION`](aether::Topic) and its
//! per-envelope outcome on [`Topic::FITNESS`](aether::Topic), plus budget-trajectory events. Every
//! ingredient for "what is the substrate feeling right now" already exists; this creature is one
//! minimal way to *read* them — subscribe it to both topics and it renders each sense event as a
//! one-line tape to stdout. It decides nothing and changes nothing (it emits no dispatches); it is a
//! pure observer, exactly the *proprioception-as-a-sense* idea made tangible.
//!
//! It parses the wire as generic JSON rather than linking the kernel's event structs, so it stays a
//! plain creature with no dependency on `sanctum` — any language could write the same observer.

use aether::{Creature, CreatureCtx, Envelope, Outcome, MAX_SENSE_EVENT_BYTES};
use serde_json::Value;

/// A pure-observer creature. Bind it, subscribe it to `proprioception` + `fitness`, and it prints
/// the substrate's sense stream as a live tape. Holds nothing; renders and returns.
#[derive(Default)]
pub struct Monitor {
    /// Optional label so multiple monitors (per-Realm, per-concern) are distinguishable on the tape.
    tag: String,
}

impl Monitor {
    pub fn new(tag: impl Into<String>) -> Self {
        Monitor { tag: tag.into() }
    }

    /// Format one sense envelope as a tape line — exposed (not just `println!`'d) so a host that
    /// wants to route the tape elsewhere (a log, a UI, a test assertion) can reuse the rendering.
    pub fn render(&self, env: &Envelope) -> String {
        let body: Value = if env.payload.len() > MAX_SENSE_EVENT_BYTES {
            Value::Null
        } else {
            serde_json::from_slice(&env.payload).unwrap_or(Value::Null)
        };
        let prefix = if self.tag.is_empty() { String::new() } else { format!("[{}] ", self.tag) };
        match env.header.schema.as_str() {
            "proprioception" => {
                let m = body.get("creature").and_then(Value::as_u64).unwrap_or(0);
                let event = body.get("event").and_then(Value::as_str).unwrap_or("?");
                format!("{prefix}sense    · creature #{m}: {event}")
            }
            "fitness" => {
                let m = body.get("creature").and_then(Value::as_u64).unwrap_or(0);
                let ok = body.get("ok").and_then(Value::as_bool).unwrap_or(false);
                let verdict = if ok { "useful" } else { "fault" };
                format!("{prefix}fitness  · creature #{m}: {verdict}")
            }
            "budget_signal" => {
                let m = body.get("creature").and_then(Value::as_u64).unwrap_or(0);
                let level = body.get("level").and_then(Value::as_str).unwrap_or("?");
                let kind = body.get("kind").and_then(Value::as_str).unwrap_or("?");
                let consumed =
                    body.pointer("/vector/consumed").and_then(Value::as_u64).unwrap_or(0);
                let limit = body.pointer("/vector/limit").and_then(Value::as_u64).unwrap_or(0);
                format!("{prefix}budget   · creature #{m}: {level} {kind} ({consumed}/{limit})")
            }
            other => format!("{prefix}event    · schema='{other}' ({} bytes)", env.payload.len()),
        }
    }
}

impl Creature for Monitor {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        println!("  ┊ {}", self.render(&env));
        Outcome::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Header};

    fn env(schema: &str, payload: &[u8]) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Kernel,
                to: Address::Creature(CreatureId(1)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: schema.into(),
                origin: None,
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn renders_each_sense_schema_into_a_tape_line() {
        let m = Monitor::default();
        assert!(m
            .render(&env("proprioception", br#"{"creature":7,"event":"loaded"}"#))
            .contains("creature #7: loaded"));
        assert!(m.render(&env("fitness", br#"{"creature":7,"ok":true}"#)).contains("useful"));
        assert!(m.render(&env("fitness", br#"{"creature":7,"ok":false}"#)).contains("fault"));
        assert!(m
            .render(&env(
                "budget_signal",
                br#"{"creature":7,"level":"hard","kind":"fuel","vector":{"consumed":900,"limit":1000}}"#
            ))
            .contains("hard fuel (900/1000)"));
        // Unknown schema degrades to a generic line, never panics.
        assert!(m.render(&env("mystery", b"\xff\x00")).contains("schema='mystery'"));
    }

    #[test]
    fn tag_prefixes_the_tape_when_set() {
        let m = Monitor::new("realm-a");
        assert!(m.render(&env("fitness", br#"{"creature":1,"ok":true}"#)).starts_with("[realm-a]"));
    }

    #[test]
    fn oversized_sense_payload_degrades_without_json_parse() {
        let m = Monitor::default();
        let line = m.render(&env("budget_signal", &vec![b'{'; MAX_SENSE_EVENT_BYTES + 1]));
        assert!(
            line.contains("creature #0"),
            "oversized known-schema payload renders from Null fallback: {line}"
        );
    }

    #[test]
    fn handle_emits_nothing_pure_observer() {
        let mut m = Monitor::default();
        let out = m.handle(env("fitness", br#"{"creature":1,"ok":true}"#));
        assert!(out.dispatches.is_empty(), "the monitor must never emit — it only observes");
    }
}
