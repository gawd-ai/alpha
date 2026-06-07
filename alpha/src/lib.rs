//! alpha — the **α** front door library.
//!
//! The composition roots for every operator surface live here, and the `alpha` binary
//! ([`main`](../main.rs)) is a thin dispatcher over them. Each operator surface is "compose a
//! [`Kernel`] + engines + injected policy + the `omni` control core + the loadable surface creatures,
//! then run":
//!
//! - [`node`] — `alpha node`: the interactive node daemon (REPL + optional HTTP/WS + optional
//!   cluster).
//! - [`mcp`] — `alpha mcp`: the MCP control-hub (a headless sanctum whose `surface-mcp` creature owns
//!   stdio).
//! - [`http`] — `alpha http`: the HTTP/WS control plane (a headless node bound to the `surface-http`
//!   creature) — the symmetric sibling of `alpha mcp`.
//!
//! [`demo`] is different: `alpha demo [list|run <name>]` is a managed runner for the narrated demos.
//! The demos are NOT linked here — they are external crates listed in `demos/demos.json` and spawned,
//! so one is added/removed by editing that manifest, not by recompiling `alpha`.
//!
//! **Why here and not in `sanctum`?** A composition root sits *above* everything it assembles: the
//! daemon needs `omni` (the control core) and the async surfaces, and `omni` already depends on
//! `sanctum` (the kernel). Putting the daemon in the `sanctum` crate would cycle. `alpha` is **α** —
//! the outermost membrane — which is exactly where "wire it all together and run" belongs.
//!
//! [`Kernel`]: sanctum::Kernel

pub mod demo;
pub mod http;
pub mod mcp;
pub mod node;

/// Operator-supplied model selection for the AUTHORING author, collected from the `--author-*` CLI
/// flags on `alpha node` / `alpha mcp`. **The model is configured per node instance at the operator
/// surface — never from the environment**, so two instances on one host (and, later, different realms
/// or sanctum specialities) can run different models. The substrate core takes the resulting
/// `mind::ModelConfig` as data via [`omni::Authoring`], so per-realm/per-sanctum routing is a future
/// change to *this* edge, not to the core.
#[derive(Default, Debug, Clone)]
pub struct AuthorFlags {
    /// `--author-model <id>` — the model name. Its presence selects the model-backed author.
    pub model: Option<String>,
    /// `--author-base-url <url>` — OpenAI-compatible endpoint (default `https://api.openai.com/v1`).
    pub base_url: Option<String>,
    /// `--author-api-key <key>` — inline secret (visible in the process list; prefer the file form).
    pub api_key: Option<String>,
    /// `--author-api-key-file <path>` — read the secret from a file (per-instance, leak-safe).
    pub api_key_file: Option<String>,
    /// `--author-timeout-secs <n>` — model read timeout (default 60).
    pub timeout_secs: Option<u64>,
}

/// The author this node binds, chosen at the operator surface from [`AuthorFlags`] — the core never
/// reads the environment to decide. Defaults to the deterministic `agent-templated` reference; with
/// `--features openai` and an `--author-model`, the model-backed author binds the same socket.
pub fn chosen_authoring(flags: &AuthorFlags) -> omni::Authoring {
    #[cfg(feature = "openai")]
    {
        if let Some(cfg) = flags.to_model_config() {
            return omni::Authoring::Model(cfg);
        }
    }
    #[cfg(not(feature = "openai"))]
    {
        if flags.model.as_deref().is_some_and(|s| !s.is_empty()) {
            eprintln!(
                "alpha: --author-model was given but this build lacks `--features openai`; \
                 using the deterministic templated author."
            );
        }
    }
    omni::Authoring::Templated
}

#[cfg(feature = "openai")]
impl AuthorFlags {
    /// Build a [`mind::ModelConfig`] when a model is selected (`--author-model` non-empty), else
    /// `None` (→ the templated default). Pure data assembly — no environment is read.
    fn to_model_config(&self) -> Option<mind::ModelConfig> {
        let model = self.model.clone().filter(|s| !s.is_empty())?;
        let base_url = self
            .base_url
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
        let timeout =
            std::time::Duration::from_secs(self.timeout_secs.filter(|n| *n > 0).unwrap_or(60));
        Some(mind::ModelConfig { base_url, model, api_key: self.resolve_api_key(), timeout })
    }

    /// Resolve the API key (always trimmed, so stray whitespace can't silently 401 the Bearer header).
    /// A `--author-api-key-file` path takes precedence over an inline `--author-api-key`; a file that
    /// is set but unreadable is **fatal** (returns `None` — it does *not* fall back to the inline key),
    /// so a misconfigured secret path fails loud rather than quietly authing as someone else. Neither
    /// set → `None` (the keyless local-server case).
    fn resolve_api_key(&self) -> Option<String> {
        if let Some(path) = self.api_key_file.as_deref().filter(|s| !s.is_empty()) {
            match std::fs::read_to_string(path) {
                Ok(s) => return Some(s.trim().to_string()).filter(|s| !s.is_empty()),
                Err(e) => {
                    eprintln!("alpha: could not read --author-api-key-file {path}: {e}");
                    return None;
                }
            }
        }
        self.api_key.as_ref().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }
}
