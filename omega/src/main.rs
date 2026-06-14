//! omega — the **Ω** server binary. A thin dispatcher over the composition root in the
//! [`omega`](crate) library.
//!
//! Dual to `alpha`: where `alpha node` boots an operator/authoring seat (a REPL + the authoring
//! organs), `omega serve` boots a dedicated **federation / gateway Sanctum** — a transport mesh node
//! that hosts `omega-federator` on `Role::OMEGA_GATEWAY`, the thing other Sanctums and Realms federate
//! with. α is the front door (client); Ω is the federation apex (server).
//!
//! - `omega serve [flags]` — boot a federation / gateway Sanctum.
//! - `omega version` · `omega help`

use std::process::ExitCode;

const HELP: &str = "\
omega — the Ω federation / gateway server (dual to the α front door)

USAGE:
    omega <command> [args...]

COMMANDS:
    serve [flags]    Boot a federation / gateway Sanctum (headless): a transport mesh node hosting
                     registry-mem and omega-federator (Role::OMEGA_GATEWAY), with an optional control plane.
                     Required: --node-id <id>  --cluster-listen <addr>
                     Optional: --realm <id> (this gateway's Realm; default `global`)
                               --seed <node-id@host:port#pubkey-hex>   (repeatable)
                               --peer-realm <realm>=<node-id>          (repeatable; Omega routes)
                               --cluster-key <64-hex seed>  --listen <http-addr>
                               --api-key <key>  --allow-ai
    version          Print the version.
    help             Print this help.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    };
    match cmd.as_str() {
        "serve" => match omega::serve::run(rest) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("omega serve: {e}");
                ExitCode::FAILURE
            }
        },
        "version" | "--version" | "-V" => {
            println!("omega {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("omega: unknown command `{other}`\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}
