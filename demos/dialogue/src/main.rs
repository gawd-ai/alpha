//! `dialogue` — thin binary wrapper over [`dialogue::run`]. `alpha demo dialogue` launches this
//! binary as an external child.

fn main() {
    if let Err(error) = dialogue::run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("dialogue: {error}");
        std::process::exit(1);
    }
}
