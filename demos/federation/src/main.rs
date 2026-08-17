//! `federation` — thin binary wrapper over [`federation::run`]. `alpha demo federation` launches
//! this binary as an external child.

fn main() {
    federation::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
