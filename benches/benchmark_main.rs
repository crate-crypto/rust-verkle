use criterion::criterion_main;

mod benchmarks;
criterion_main! {
    benchmarks::proof_10k::benches,
    benchmarks::edit_10k::benches,
    benchmarks::insert_10k::benches,
}
