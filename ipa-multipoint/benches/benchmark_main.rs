use criterion::criterion_main;

mod benchmarks;
criterion_main! {
    benchmarks::ipa_prove::benches,
    benchmarks::ipa_verify::benches,
    benchmarks::multipoint_verify::benches,
    benchmarks::multipoint_prove::benches,
}
