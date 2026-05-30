//! `federation` — thin binary wrapper over [`federation::run`]; the same demo `alpha demo
//! federation` runs in-process.

fn main() {
    federation::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
