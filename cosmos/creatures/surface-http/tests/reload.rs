//! The surface owns its boundary and **releases it on unload**. The regression guard for
//! the highest-risk piece (a tokio/Axum runtime inside a creature): load the HTTP surface on a port,
//! unload it, and prove the port is free by loading a *second* surface on the *same* port. A leaked
//! listener (runtime thread not joined, fd not closed) would make the re-bind fail.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use aether::{Deadline, StubSigner, StubVerifier};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::Capabilities;

use omni::{boot_control, boot_manifest, AiControl};
use surface_http::{ControlTarget, SurfaceHttp};

fn node() -> Arc<Kernel> {
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("reload-test")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    );
    let ai = Arc::new(AiControl::new(false));
    boot_control(&kernel, &ai, None, None).expect("control boots");
    kernel
}

/// Load an HTTP surface on `addr` (the listener pre-bound by the caller), let `bind` run, then return
/// its creature id so the caller can unload it.
fn load_surface(kernel: &Kernel, addr: &str) -> aether::CreatureId {
    let listener = TcpListener::bind(addr).expect("bind the surface port");
    let (_sid, _bus, sense_rx) = kernel.open_endpoint(Capabilities::default());
    let surface = SurfaceHttp::new(listener, "k".into(), ControlTarget::Local, sense_rx)
        .expect("surface setup");
    let id = kernel
        .load_instance(boot_manifest("surface-http"), Box::new(surface))
        .expect("surface admits");
    // Let the drain thread run `bind` so the tokio runtime actually owns the listener (exercises the
    // real teardown path, not just a pre-bind drop).
    std::thread::sleep(Duration::from_millis(150));
    id
}

#[test]
fn surface_releases_its_port_on_unload_so_it_can_reload() {
    let kernel = node();
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{port}");

    // Load #1, then unload — `shutdown` must stop the server and join the runtime thread, closing
    // the listener fd.
    let id1 = load_surface(&kernel, &addr);
    kernel.unload(id1, Deadline::from_millis(3000)).expect("clean unload");

    // The port is now free: re-load a second surface on the SAME port. A leaked listener would make
    // this bind fail.
    let id2 = load_surface(&kernel, &addr);
    kernel.unload(id2, Deadline::from_millis(3000)).expect("clean unload of the reload");

    kernel.shutdown_all(Deadline::default());
}
