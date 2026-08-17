//! `bestiary-live` — thin binary wrapper over [`bestiary_live::run`]. `alpha demo bestiary-live`
//! launches this binary as an external child with the registry-selected model feature.

fn main() {
    bestiary_live::run(&std::env::args().skip(1).collect::<Vec<_>>())
}
