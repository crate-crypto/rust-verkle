use ffi_interface::{
    deserialize_proof_query, deserialize_proof_query_uncompressed, deserialize_verifier_query,
    deserialize_verifier_query_uncompressed, fr_from_le_bytes, get_tree_key_hash, Context,
};
use ipa_multipoint::committer::Committer;
use ipa_multipoint::multiproof::{MultiPoint, MultiPointProof, ProverQuery, VerifierQuery};
use ipa_multipoint::transcript::Transcript;

#[no_mangle]
pub extern "C" fn context_new() -> *mut Context {
    let ctx = Box::new(Context::default());
    Box::into_raw(ctx)
}

#[no_mangle]
pub extern "C" fn context_free(ctx: *mut Context) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(ctx);
    }
}

#[no_mangle]
pub extern "C" fn pedersen_hash(
    ctx: *mut Context,
    address: *const u8,
    tree_index_le: *const u8,
    out: *mut u8,
) {
    if ctx.is_null() || address.is_null() || tree_index_le.is_null() || out.is_null() {
        // TODO: We have ommited the error handling for null pointers at the moment.
        // TODO: Likely will panic in this case.
        return;
    }

    let (tree_index, add, context) = unsafe {
        let add_slice = std::slice::from_raw_parts(address, 32);
        let ctx_ref = &*ctx;
        let tree_index_slice = std::slice::from_raw_parts(tree_index_le, 32);

        (tree_index_slice, add_slice, ctx_ref)
    };

    let hash = get_tree_key_hash(
        context,
        <[u8; 32]>::try_from(add).unwrap(),
        <[u8; 32]>::try_from(tree_index).unwrap(),
    );

    unsafe {
        let commitment_data_slice = std::slice::from_raw_parts_mut(out, 32);
        commitment_data_slice.copy_from_slice(&hash);
    }
}

#[no_mangle]
pub extern "C" fn multi_scalar_mul(
    ctx: *mut Context,
    scalars: *const u8,
    len: usize,
    out: *mut u8,
) {
    let (scalar_slice, context) = unsafe {
        let scalar = std::slice::from_raw_parts(scalars, len);
        let ctx_ref = &*ctx;

        (scalar, ctx_ref)
    };

    let mut inputs = Vec::with_capacity(len);
    for chunk in scalar_slice.chunks_exact(32) {
        inputs.push(fr_from_le_bytes(chunk).unwrap());
    }

    let data = context.committer.commit_lagrange(&inputs);
    let hash = data.to_bytes();

    unsafe {
        let commitment_data_slice = std::slice::from_raw_parts_mut(out, 32);
        commitment_data_slice.copy_from_slice(&hash);
    }
}

#[no_mangle]
pub extern "C" fn create_proof(ctx: *mut Context, input: *const u8, len: usize, out: *mut u8) {
    const CHUNK_SIZE: usize = 8257; // TODO: get this from ipa-multipoint
    const PROOF_SIZE: usize = 576; // TODO: get this from ipa-multipoint

    let (scalar_slice, context) = unsafe {
        let scalar = std::slice::from_raw_parts(input, len);
        let ctx_ref = &*ctx;

        (scalar, ctx_ref)
    };

    let num_openings = len / CHUNK_SIZE;

    let proofs_bytes = scalar_slice.chunks_exact(CHUNK_SIZE);
    assert!(
        proofs_bytes.remainder().is_empty(),
        "There should be no left over bytes when chunking the proof"
    );

    // - Deserialize proof queries
    //
    let mut prover_queries: Vec<ProverQuery> = Vec::with_capacity(num_openings);

    for proof_bytes in proofs_bytes {
        let prover_query = deserialize_proof_query(proof_bytes);
        prover_queries.push(prover_query);
    }

    // - Create proofs
    //

    let mut transcript = Transcript::new(b"verkle");

    let proof = MultiPoint::open(
        // TODO: This should not need to clone the CRS, but instead take a reference
        context.crs.clone(),
        &context.precomputed_weights,
        &mut transcript,
        prover_queries,
    );

    let hash = proof.to_bytes().expect("cannot serialize proof");
    unsafe {
        let commitment_data_slice = std::slice::from_raw_parts_mut(out, PROOF_SIZE);
        commitment_data_slice.copy_from_slice(&hash);
    }
}

#[no_mangle]
pub extern "C" fn create_proof_uncompressed(
    ctx: *mut Context,
    input: *const u8,
    len: usize,
    out: *mut u8,
) {
    // 8257 + 32 because first commitment is uncompressed as 64 bytes
    const CHUNK_SIZE: usize = 8289; // TODO: get this from ipa-multipoint
    const PROOF_SIZE: usize = 576; // TODO: get this from ipa-multipoint

    let (scalar_slice, context) = unsafe {
        let scalar = std::slice::from_raw_parts(input, len);
        let ctx_ref = &*ctx;

        (scalar, ctx_ref)
    };

    let num_openings = len / CHUNK_SIZE;

    let proofs_bytes = scalar_slice.chunks_exact(CHUNK_SIZE);
    assert!(
        proofs_bytes.remainder().is_empty(),
        "There should be no left over bytes when chunking the proof"
    );

    // - Deserialize proof queries
    //
    let mut prover_queries: Vec<ProverQuery> = Vec::with_capacity(num_openings);

    for proof_bytes in proofs_bytes {
        let prover_query = deserialize_proof_query_uncompressed(proof_bytes);
        prover_queries.push(prover_query);
    }

    // - Create proofs
    //

    let mut transcript = Transcript::new(b"verkle");

    let proof = MultiPoint::open(
        // TODO: This should not need to clone the CRS, but instead take a reference
        context.crs.clone(),
        &context.precomputed_weights,
        &mut transcript,
        prover_queries,
    );

    let hash = proof.to_bytes().expect("cannot serialize proof");
    unsafe {
        let commitment_data_slice = std::slice::from_raw_parts_mut(out, PROOF_SIZE);
        commitment_data_slice.copy_from_slice(&hash);
    }
}

#[no_mangle]
pub extern "C" fn verify_proof(ctx: *mut Context, input: *const u8, len: usize) -> bool {
    const CHUNK_SIZE: usize = 65; // TODO: get this from ipa-multipoint
    const PROOF_SIZE: usize = 576; // TODO: get this from ipa-multipoint

    let (proof_slice, verifier_queries_slices, context) = unsafe {
        let input_slice = std::slice::from_raw_parts(input, len);

        let (proof_slice, verifier_queries_slices) = input_slice.split_at(PROOF_SIZE);

        let ctx_ref = &*ctx;

        (proof_slice, verifier_queries_slices, ctx_ref)
    };

    let verifier_queries_bytes = verifier_queries_slices.chunks_exact(CHUNK_SIZE);
    assert!(
        verifier_queries_bytes.remainder().is_empty(),
        "There should be no left over bytes when chunking the verifier queries"
    );

    let num_openings = verifier_queries_bytes.len() / CHUNK_SIZE;

    // - Deserialize verifier queries
    //

    let mut verifier_queries: Vec<VerifierQuery> = Vec::with_capacity(num_openings);

    for verifier_query_bytes in verifier_queries_bytes {
        let verifier_query = deserialize_verifier_query(verifier_query_bytes);
        verifier_queries.push(verifier_query);
    }

    // - Check proof
    //

    let proof = MultiPointProof::from_bytes(proof_slice, 256).unwrap();

    let mut transcript = Transcript::new(b"verkle");

    // TODO: This should not need to clone the CRS, but instead take a reference
    let is_valid = MultiPointProof::check(
        &proof,
        &context.crs.clone(),
        &context.precomputed_weights,
        &verifier_queries,
        &mut transcript,
    );

    return is_valid;
}

#[no_mangle]
pub extern "C" fn verify_proof_uncompressed(
    ctx: *mut Context,
    input: *const u8,
    len: usize,
) -> bool {
    // Chunk is now 65 + 32 = 97 because first commitment is uncompressed as 64 bytes
    const CHUNK_SIZE: usize = 97; // TODO: get this from ipa-multipoint
    const PROOF_SIZE: usize = 576; // TODO: get this from ipa-multipoint

    let (proof_slice, verifier_queries_slices, context) = unsafe {
        let input_slice = std::slice::from_raw_parts(input, len);

        let (proof_slice, verifier_queries_slices) = input_slice.split_at(PROOF_SIZE);

        let ctx_ref = &*ctx;

        (proof_slice, verifier_queries_slices, ctx_ref)
    };

    let verifier_queries_bytes = verifier_queries_slices.chunks_exact(CHUNK_SIZE);
    assert!(
        verifier_queries_bytes.remainder().is_empty(),
        "There should be no left over bytes when chunking the verifier queries"
    );

    let num_openings = verifier_queries_bytes.len() / CHUNK_SIZE;

    // - Deserialize verifier queries
    //

    let mut verifier_queries: Vec<VerifierQuery> = Vec::with_capacity(num_openings);

    for verifier_query_bytes in verifier_queries_bytes {
        let verifier_query = deserialize_verifier_query_uncompressed(verifier_query_bytes);
        verifier_queries.push(verifier_query);
    }

    // - Check proof
    //

    let proof = MultiPointProof::from_bytes(proof_slice, 256).unwrap();

    let mut transcript = Transcript::new(b"verkle");

    // TODO: This should not need to clone the CRS, but instead take a reference
    let is_valid = MultiPointProof::check(
        &proof,
        &context.crs.clone(),
        &context.precomputed_weights,
        &verifier_queries,
        &mut transcript,
    );

    return is_valid;
}
