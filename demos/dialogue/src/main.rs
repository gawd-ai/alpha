//! `dialogue` — thin binary wrapper over [`dialogue::run`]; the same demo `alpha demo dialogue`
//! runs in-process.

fn main() {
    dialogue::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
