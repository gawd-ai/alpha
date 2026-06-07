//! `bestiary-live` — thin binary wrapper over [`bestiary_live::run`]; the same demo `alpha demo
//! bestiary-live` runs in-process.

fn main() {
    bestiary_live::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
