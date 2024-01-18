use banderwagon::{trait_defs::*, Fr};
use ipa_multipoint::committer::{Committer, DefaultCommitter};
use ipa_multipoint::crs::CRS;
use std::time::Instant;

fn main() {
    println!("Benchmarking Pedersen hashing...");
    const N: usize = 5000;

    let committer = DefaultCommitter::new(CRS::new(256, "eth_verkle_oct_2021".as_bytes()));
    let mut vec_len = 1;
    while vec_len <= 256 {
        println!("\twith {} elements... ", vec_len);

        let mut vecs = vec![[Fr::from(0u128); 256]; N];
        for i in 0..vecs.len() {
            for j in 0..vec_len {
                vecs[i][j] = Fr::from((i + j + 0x424242) as u128);
            }
            for j in vec_len..vecs[i].len() {
                vecs[i][j] = Fr::zero();
            }
        }

        let start = Instant::now();
        for i in 0..N {
            committer.commit_lagrange(&vecs[i][0..vec_len]);
        }
        let duration = start.elapsed();
        println!("takes {}µs", duration.as_micros() / (N as u128));

        vec_len <<= 1;
    }
}
