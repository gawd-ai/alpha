//! alpha — the **α** front door binary. A thin dispatcher over the composition roots
//! in the [`alpha`](crate) library.
//!
//! GAWD's cosmology is a **closed membrane**: `alpha` is **α** (the genesis / entry point) and
//! `omega` is **Ω** (the highest set-of-sets, the final membrane). Everything that exists, exists
//! *between* α and Ω; the only things that cross the boundary are **stimuli** (inputs) and
//! **products** (outputs). The placement test that follows: *if a thing is neither a stimulus nor a
//! product, it lives between α and Ω — inside the Alpha project, with mechanism under `cosmos/` and
//! outer composition roots here.* So this binary is the one outermost entry point. The operator
//! surfaces dispatch **in-process** (no exec shim — a shell script could already exec; the value here
//! is one process that can hold many sanctums and grow operator concerns that should not go deeper);
//! the demo runner is deliberately external and spawns from `demos/demos.json`:
//!
//! - `alpha node [flags]`   — boot a sanctum node daemon (REPL + optional HTTP/WS + cluster).
//! - `alpha mcp [flags]`    — boot the MCP control-hub (a headless sanctum speaking JSON-RPC on stdio).
//! - `alpha http [flags]`   — serve the HTTP/WS control plane (a headless node + `surface-http`).
//! - `alpha demo [list|run <name>]` — launch a narrated demo (external `demos/demos.json` registry).
//! - `alpha version` · `alpha help`
//!
//! **Growth area (not all built yet).** The front door is where operational concerns that "should
//! not go deeper" land: launching several sanctums in one process, dropping into a chosen sanctum's
//! REPL (the reserved in-process multiplexing question), installing as a service, and
//! self-update. They are named here so they arrive as front-door subcommands, never as a new
//! outermost concept.

use std::process::ExitCode;

const HELP: &str = "\
alpha — the α front door to an Alpha deployment

USAGE:
    alpha <command> [args...]

COMMANDS:
    node [flags]     Boot a sanctum node daemon (REPL + optional HTTP/WS + cluster).
                     All node flags pass through: --listen --cluster-listen --exec …
                     Model author (needs `--features openai`): --author-model <id>
                     [--author-base-url <url>] [--author-api-key-file <path> | --author-api-key <key>]
                     [--author-timeout-secs <n>]. Selected per node instance — never from the env.
    mcp [flags]      Boot the MCP control-hub (a headless sanctum speaking JSON-RPC on stdio).
    http --listen <addr>
                     Serve the HTTP/WS control plane (a headless node + the surface-http creature).
    demo [list|run <name>]
                     Launch a narrated demo. Demos are external crates listed in
                     demos/demos.json (not linked into alpha); `alpha demo` spawns them.
                     `alpha demo list` shows what's available.
    version          Print the version.
    help             Print this help.

Operator surfaces run in-process; demos are external children. `alpha` is the outermost membrane (α);
`omega` is the ceiling (Ω).
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    };
    match cmd.as_str() {
        "node" => io_exit("alpha node", alpha::node::run(rest)),
        "mcp" => {
            alpha::mcp::run(rest);
            ExitCode::SUCCESS
        }
        "http" => io_exit("alpha http", alpha::http::run(rest)),
        "demo" => alpha::demo::run(rest),
        "version" | "--version" | "-V" => {
            println!("alpha {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("alpha: unknown command `{other}`\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

/// Map an `io::Result` surface body to an exit code, reporting the error under `who`.
fn io_exit(who: &str, r: std::io::Result<()>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{who}: {e}");
            ExitCode::FAILURE
        }
    }
}
