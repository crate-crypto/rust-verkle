use criterion::criterion_main;

mod benchmarks;
criterion_main! {
    benchmarks::insert_10k::benches,
    // benchmarks::edit_10k::benches,
    benchmarks::proof_10k::benches,
}
