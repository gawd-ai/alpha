//! `dialogue` — thin binary wrapper over [`dialogue::run`]. `alpha demo dialogue` launches this
//! binary as an external child.

fn main() {
    dialogue::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
