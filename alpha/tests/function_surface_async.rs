//! External-surface proof for typed Function / durable Job async semantics.
//!
//! The fixture boots Alpha's opt-in durable runtime with no reachable executor target. A submit
//! can therefore never reach terminal execution. HTTP and the REPL `--exec` grammar must still
//! return the exact Home-signed durable `Submitted` acceptance; a restart then proves that HTTP did
//! not return an in-memory acknowledgement.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gawdfn::{
    derive_deployment_id, derive_job_id, verify_job_acceptance, verify_job_snapshot,
    verify_job_snapshot_response_for, AbodeKeyBindingV1, AuthoritySigner, DeliveryModeV1,
    DeploymentReceiptV1, Ed25519SeedSigner, FunctionId, FunctionSelectorV1, HomeAuthorityV1,
    HomeId, JobAccessV1, JobEventV1, JobGetRelayV1, JobGetV1, JobHandleV1, JobSnapshotResponseV1,
    JobSnapshotV1, JobSubmitV1, OperationalCapabilityV1, OperationalKeyGrantV1,
    ResolutionReceiptV1, SignedRecordV1, ValueRefV1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1,
    SCHEMA_JOB_V1,
};
use serde_json::{json, Value};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("alpha-function-surface-{}-{sequence}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _root: TempRoot,
    config: PathBuf,
    home: HomeId,
}

impl Fixture {
    fn new() -> Self {
        let root = TempRoot::new();
        let root_signer = Ed25519SeedSigner::from_seed([1; 32]).unwrap();
        let home_signer = Ed25519SeedSigner::from_seed([2; 32]).unwrap();
        let resolver_signer = Ed25519SeedSigner::from_seed([3; 32]).unwrap();
        let executor_signer = Ed25519SeedSigner::from_seed([4; 32]).unwrap();
        let policy_signer = Ed25519SeedSigner::from_seed([5; 32]).unwrap();
        let deployer_signer = Ed25519SeedSigner::from_seed([6; 32]).unwrap();
        let catalog_signer = Ed25519SeedSigner::from_seed([7; 32]).unwrap();
        let home = HomeId::new(root_signer.public_key());
        let authority = HomeAuthorityV1 {
            abode: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                AbodeKeyBindingV1 {
                    abode: home.clone(),
                    root_public_key: root_signer.public_key().into(),
                    issued_at_unix_ms: None,
                },
                &root_signer,
            )
            .unwrap(),
            operational: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                OperationalKeyGrantV1 {
                    home: home.clone(),
                    epoch: 1,
                    operational_public_key: home_signer.public_key().into(),
                    valid_from_unix_ms: None,
                    expires_at_unix_ms: None,
                    capabilities: vec![
                        OperationalCapabilityV1::JobHome,
                        OperationalCapabilityV1::JobControl,
                        OperationalCapabilityV1::Custody,
                        OperationalCapabilityV1::Locate,
                    ],
                    evidence: vec![],
                },
                &root_signer,
            )
            .unwrap(),
            prepared: None,
        };

        let keys = root.0.join("keys");
        fs::create_dir_all(&keys).unwrap();
        seed_file(&keys, "home.hex", 2);
        seed_file(&keys, "resolver.hex", 3);
        seed_file(&keys, "executor.hex", 4);
        seed_file(&keys, "policy.hex", 5);
        seed_file(&keys, "deployer.hex", 6);
        seed_file(&keys, "catalog.hex", 7);
        let config = root.0.join("functions.json");
        fs::write(
            &config,
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "state_dir": "state",
                "realm": "crew",
                "node": "op",
                "authority": authority,
                "historical_authorities": [],
                "home_operational_key_file": "keys/home.hex",
                "resolver": {
                    "public_key": resolver_signer.public_key(),
                    "seed_file": "keys/resolver.hex"
                },
                "executor": {
                    "public_key": executor_signer.public_key(),
                    "seed_file": "keys/executor.hex"
                },
                "policy": {
                    "public_key": policy_signer.public_key(),
                    "seed_file": "keys/policy.hex"
                },
                "deployer": {
                    "public_key": deployer_signer.public_key(),
                    "seed_file": "keys/deployer.hex"
                },
                "catalog": {
                    "public_key": catalog_signer.public_key(),
                    "seed_file": "keys/catalog.hex"
                }
            }))
            .unwrap(),
        )
        .unwrap();
        Self { _root: root, config, home }
    }

    fn job(&self, idempotency_key: &str) -> JobBundle {
        let root = Ed25519SeedSigner::from_seed([1; 32]).unwrap();
        let resolver = Ed25519SeedSigner::from_seed([3; 32]).unwrap();
        let executor = Ed25519SeedSigner::from_seed([4; 32]).unwrap();
        let function = FunctionId {
            manifest_content_address: format!("sha256:{}", "a".repeat(64)),
            entrypoint: "run".into(),
        };
        let selector = FunctionSelectorV1::Id { function: function.clone() };
        let artifact_hash = format!("sha256:{}", "b".repeat(64));
        // These identities are valid u64 addresses but cannot collide with the handful of organs
        // in this fixture. Execution is intentionally unreachable, so terminal completion is
        // impossible while the surface acceptance proof runs.
        let executor_creature = (u64::MAX - 1).to_string();
        let target_creature = (u64::MAX - 2).to_string();
        let deployment_id =
            derive_deployment_id(&function, &artifact_hash, "crew", "op", &target_creature)
                .unwrap();
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobSubmitV1 {
                home: self.home.clone(),
                caller_idempotency_key: idempotency_key.into(),
                function: selector.clone(),
                input: ValueRefV1::Inline { value: json!({ "value": 41 }) },
                delivery: DeliveryModeV1::AtMostOnce,
                allow_duplicate_effects: false,
                parent: None,
                causal: vec![],
                access: JobAccessV1::default(),
                evidence: vec![],
                result_recipients: vec![],
                submitted_at_unix_ms: None,
            },
            &root,
        )
        .unwrap();
        let resolution = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            ResolutionReceiptV1 {
                selector,
                function: function.clone(),
                artifact_hash: artifact_hash.clone(),
                resolved_at_unix_ms: None,
                evidence: vec![],
            },
            &resolver,
        )
        .unwrap();
        let deployment = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentReceiptV1 {
                deployment: deployment_id,
                function,
                artifact_hash,
                realm: "crew".into(),
                node: "op".into(),
                executor: executor.public_key().into(),
                executor_creature,
                creature: target_creature,
                evidence: vec![],
                registered_at_unix_ms: None,
            },
            &executor,
        )
        .unwrap();
        JobBundle { request, resolution, deployment }
    }
}

fn seed_file(root: &Path, name: &str, byte: u8) {
    let path = root.join(name);
    fs::write(&path, sigil::crypto::hex_encode(&[byte; 32])).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

struct JobBundle {
    request: SignedRecordV1<JobSubmitV1>,
    resolution: SignedRecordV1<ResolutionReceiptV1>,
    deployment: SignedRecordV1<DeploymentReceiptV1>,
}

impl JobBundle {
    fn json(&self) -> Value {
        json!({
            "request": self.request,
            "resolution": self.resolution,
            "deployment": self.deployment
        })
    }
}

struct Daemon {
    child: Child,
    port: u16,
}

impl Daemon {
    fn spawn(config: &Path) -> Self {
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_alpha"))
            .args([
                "node",
                "--functions",
                config.to_str().unwrap(),
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--api-key",
                "surface-test-key",
                "--allow-ai",
                "--headless",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn Function-enabled Alpha node");
        let daemon = Self { child, port };
        daemon.wait_ready();
        daemon
    }

    fn wait_ready(&self) {
        for _ in 0..200 {
            if http(self.port, "GET", "/api/health", None).is_some_and(|(status, _)| status == 200)
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("Function-enabled Alpha node did not become ready");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// One bounded raw HTTP request. A surface that waited for the deliberately unreachable terminal
/// state would exceed this three-second socket budget; durable acceptance normally returns in ms.
fn http(port: u16, method: &str, path: &str, body: Option<&Value>) -> Option<(u16, Value)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let payload = body.map(Value::to_string).unwrap_or_default();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    if path != "/api/health" {
        request.push_str("Authorization: Bearer surface-test-key\r\n");
    }
    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    request.push_str("\r\n");
    request.push_str(&payload);
    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let status = response.split_whitespace().nth(1)?.parse().ok()?;
    let body = response.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or("");
    let start = body.find('{')?;
    let end = body.rfind('}')?;
    Some((status, serde_json::from_str(&body[start..=end]).ok()?))
}

fn assert_acceptance(value: &Value, home: &HomeId, key: &str) -> JobHandleV1 {
    assert_eq!(value["accepted"], true, "surface did not return Accepted: {value}");
    let handle: JobHandleV1 = serde_json::from_value(value["handle"].clone()).unwrap();
    assert_eq!(handle.home, *home);
    assert_eq!(handle.job, derive_job_id(home, key).unwrap());
    let request_hash = value["request_hash"].as_str().unwrap();
    let submitted: SignedRecordV1<JobEventV1> =
        serde_json::from_value(value["submitted"].clone()).unwrap();
    verify_job_acceptance(&handle, request_hash, &submitted).unwrap();
    handle
}

fn get_snapshot(daemon: &Daemon, handle: &JobHandleV1) -> SignedRecordV1<JobSnapshotV1> {
    let root = Ed25519SeedSigner::from_seed([1; 32]).unwrap();
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetV1 { handle: handle.clone(), nonce: "surface-proof-read".into() },
        &root,
    )
    .unwrap();
    let (status, body) =
        http(daemon.port, "POST", "/api/jobs/get", Some(&json!({ "request": request })))
            .expect("HTTP JobGet answers within the surface budget");
    assert_eq!(status, 200, "JobGet failed: {body}");
    let relay: SignedRecordV1<JobGetRelayV1> =
        serde_json::from_value(body["relay_request"].clone()).unwrap();
    let response: SignedRecordV1<JobSnapshotResponseV1> =
        serde_json::from_value(body["response"].clone()).unwrap();
    verify_job_snapshot_response_for(&response, &relay).unwrap();
    assert!(body.get("snapshot").is_none(), "the signed snapshot must not be duplicated");
    let snapshot = *response.payload.snapshot;
    verify_job_snapshot(&snapshot).unwrap();
    snapshot
}

#[test]
fn http_and_repl_submit_return_durable_accepted_without_terminal_execution() {
    let fixture = Fixture::new();
    let http_job = fixture.job("http-async-proof");
    let daemon = Daemon::spawn(&fixture.config);

    let (status, body) = http(daemon.port, "POST", "/api/jobs/submit", Some(&http_job.json()))
        .expect("HTTP JobSubmit returns before the unreachable execution can terminate");
    assert_eq!(status, 200, "HTTP JobSubmit failed: {body}");
    let handle = assert_acceptance(&body, &fixture.home, "http-async-proof");
    let before_restart = get_snapshot(&daemon, &handle);
    assert!(
        !before_restart.payload.state.is_terminal(),
        "the external response preceded terminal execution"
    );

    // Hard process restart: the same signed snapshot must reopen from the Home journal. This is
    // the distinction between durable Accepted and an optimistic surface acknowledgement.
    drop(daemon);
    let daemon = Daemon::spawn(&fixture.config);
    let after_restart = get_snapshot(&daemon, &handle);
    assert_eq!(after_restart.payload.spec.handle, handle);
    assert!(!after_restart.payload.state.is_terminal());
    drop(daemon);

    // `--exec` uses the exact REPL grammar while keeping stdout machine-readable. Its executor pin
    // is likewise unreachable, so a successful process exit proves the local surface returns the
    // Home's durable acceptance rather than waiting for a terminal fact.
    let repl_job = fixture.job("repl-async-proof");
    let line = format!("job submit {}", repl_job.json());
    let output = Command::new(env!("CARGO_BIN_EXE_alpha"))
        .args(["node", "--functions", fixture.config.to_str().unwrap(), "--exec", &line, "--json"])
        .output()
        .expect("run Function-enabled REPL --exec");
    assert!(
        output.status.success(),
        "REPL submit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let repl: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!("REPL stdout was not one JSON result ({error}): {:?}", output.stdout)
    });
    assert_acceptance(&repl, &fixture.home, "repl-async-proof");
}
