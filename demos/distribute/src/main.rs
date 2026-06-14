//! `distribute` — thin binary wrapper over [`distribute::run`]; the same demo `alpha demo
//! distribute` runs in-process.

fn main() {
    distribute::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
