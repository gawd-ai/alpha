//! `distribute` — thin binary wrapper over [`distribute::run`]. `alpha demo distribute` launches
//! this binary as an external child.

fn main() {
    distribute::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
