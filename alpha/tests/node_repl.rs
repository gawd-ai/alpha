//! `alpha node` exposes a real runtime **control loop** (REPL) on stdin. These tests pipe commands
//! into the binary and check that it boots, accepts input, recognizes the verbs, and shuts down
//! cleanly.

use std::io::Write;
use std::process::{Command, Stdio};

/// `alpha node` — the daemon subcommand, the REPL these tests drive.
fn node_cmd() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_alpha"));
    c.arg("node");
    c
}

#[test]
fn node_boots_and_quits_cleanly() {
    let mut child = node_cmd()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn alpha node");
    child.stdin.as_mut().unwrap().write_all(b"quit\n").unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("wait alpha node");
    assert!(output.status.success(), "alpha node should exit cleanly on `quit`");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("alpha node"), "banner present");
    assert!(stdout.contains("bye."), "graceful quit ack");
}

#[test]
fn node_help_lists_the_control_loop_verbs() {
    let mut child = node_cmd()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // Unknown command surfaces the help line; then quit cleanly.
    stdin.write_all(b"badcommand\nquit\n").unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The control loop offers the full verb set.
    for verb in ["load", "send", "intent", "bind", "unload", "quit"] {
        assert!(stdout.contains(verb), "control loop should advertise `{verb}`");
    }
}

#[test]
fn node_load_with_a_bad_path_is_a_clean_error_not_a_crash() {
    let mut child = node_cmd()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"load /no/such/manifest.json /no/such/artifact.so\nquit\n").unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "bad inputs must not crash alpha node");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("load failed"), "structured error reported");
    assert!(stdout.contains("bye."));
}
