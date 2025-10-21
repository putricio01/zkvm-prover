#![allow(clippy::redundant_clone)]

use alloy_primitives::{B256, U256};
use sbv_primitives::U256 as LegacyU256;
use scroll_zkvm_types::{
    batch::{
        BatchHeaderV6, BatchInfo, BatchWitness, Envelope, EnvelopeV6, Payload, PayloadV6,
        ReferenceHeader,
    },
    bundle::{BundleInfo, BundleWitness},
    chunk::{BlockContextV2, ChunkInfo},
    public_inputs::{ForkName, MultiVersionPublicInputs},
    types_agg::{AggregationInput, ProgramCommitment},
    utils::{keccak256, point_eval},
};
use scroll_zkvm_types_circuit::public_inputs::PublicInputs;

const CHUNK_EXE_COMMIT: [u32; 8] = [
    528_782_329,
    1_463_264_633,
    430_718_151,
    1_802_869_285,
    1_022_725_725,
    7_994_895,
    545_775_728,
    820_425_422,
];
const CHUNK_VM_COMMIT: [u32; 8] = [
    1_143_979_762,
    1_252_839_784,
    728_295_280,
    80_130_475,
    1_981_604_375,
    1_538_642_995,
    55_047_256,
    1_521_517_292,
];

const BATCH_EXE_COMMIT: [u32; 8] = [
    1_245_398_086,
    61_757_779,
    302_635_179,
    1_704_723_892,
    1_582_520_717,
    1_026_261_831,
    1_746_967_963,
    111_119_280,
];
const BATCH_VM_COMMIT: [u32; 8] = [
    702_922_786,
    974_900_043,
    1_870_917_533,
    1_628_966_797,
    1_650_497_578,
    697_799_835,
    298_481_193,
    1_937_656_708,
];

fn pi_hashes_from_proofs(proofs: &[AggregationInput]) -> Vec<B256> {
    proofs
        .iter()
        .map(|proof| {
            let bytes = proof
                .public_values
                .iter()
                .map(|&value| u8::try_from(value).expect("public values encode bytes"))
                .collect::<Vec<_>>();
            B256::from_slice(&bytes)
        })
        .collect()
}

fn validate_aggregated_pi<P: PublicInputs>(agg_pis: &[P], agg_pi_hashes: &[B256]) {
    assert!(
        !agg_pis.is_empty(),
        "at least one aggregated public input must be present"
    );

    for window in agg_pis.windows(2) {
        window[1].validate(&window[0]);
    }

    for (agg_pi, expected_hash) in agg_pis.iter().zip(agg_pi_hashes.iter()) {
        assert_eq!(agg_pi.pi_hash(), *expected_hash, "pi hash mismatch");
    }
}

fn b256_from_legacy(value: &sbv_primitives::B256) -> B256 {
    B256::from_slice(value.as_slice())
}

fn b256_from_u256(value: LegacyU256) -> B256 {
    let bytes: [u8; 32] = value.to_be_bytes();
    B256::from(bytes)
}

fn to_public_values(pi_hash: &B256) -> Vec<u32> {
    pi_hash.as_slice().iter().map(|&byte| byte as u32).collect()
}

#[test]
fn forged_multi_layer_proof_survives() {
    let fork = ForkName::EuclidV1;

    // --- Step 1: forge a chunk witness while keeping the Euclid-v1 digest honest.
    let block_ctx = BlockContextV2 {
        timestamp: 0x1234_5678,
        base_fee: U256::from(42u64),
        gas_limit: 30_000_000,
        num_txs: 1,
        num_l1_msgs: 0,
    };

    let tx_data = Vec::new();
    let tx_digest = keccak256(&tx_data);

    let honest_chunk_info = ChunkInfo {
        chain_id: 534351,
        prev_state_root: B256::repeat_byte(0x11),
        post_state_root: B256::repeat_byte(0x22),
        withdraw_root: B256::repeat_byte(0x33),
        data_hash: B256::repeat_byte(0x44),
        tx_data_digest: tx_digest,
        prev_msg_queue_hash: B256::ZERO,
        post_msg_queue_hash: B256::ZERO,
        tx_data_length: u64::try_from(tx_data.len()).unwrap(),
        initial_block_number: 9,
        block_ctxs: vec![block_ctx.clone()],
    };

    let honest_chunk_pi_hash = honest_chunk_info.pi_hash_by_fork(fork);

    let mut forged_chunk_info = honest_chunk_info.clone();
    forged_chunk_info.tx_data_length = 777;
    forged_chunk_info.initial_block_number = honest_chunk_info.initial_block_number + 1000;
    forged_chunk_info.block_ctxs[0].num_txs = 9;

    assert_ne!(
        honest_chunk_info.tx_data_length,
        forged_chunk_info.tx_data_length,
        "tampering chunk tx length"
    );
    assert_ne!(
        honest_chunk_info.initial_block_number,
        forged_chunk_info.initial_block_number,
        "tampering chunk initial block"
    );
    assert_ne!(
        honest_chunk_info.block_ctxs[0].num_txs,
        forged_chunk_info.block_ctxs[0].num_txs,
        "tampering chunk block context"
    );

    let chunk_proof = AggregationInput {
        public_values: to_public_values(&honest_chunk_pi_hash),
        commitment: ProgramCommitment {
            exe: CHUNK_EXE_COMMIT,
            vm: CHUNK_VM_COMMIT,
        },
    };

    // --- Step 2: forge a batch witness that consumes the forged chunk.
    const LEGACY_MAX_CHUNKS: usize = 45;
    let mut metadata_bytes = Vec::with_capacity(2 + LEGACY_MAX_CHUNKS * 4);
    metadata_bytes.extend_from_slice(&1u16.to_be_bytes());
    metadata_bytes.extend_from_slice(&0u32.to_be_bytes());
    for _ in 1..LEGACY_MAX_CHUNKS {
        metadata_bytes.extend_from_slice(&0u32.to_be_bytes());
    }

    let mut blob_bytes = Vec::with_capacity(1 + metadata_bytes.len());
    blob_bytes.push(0); // not compressed
    blob_bytes.extend(metadata_bytes);

    let envelope = EnvelopeV6::from_slice(&blob_bytes);
    let payload = PayloadV6::from_envelope(&envelope);

    let blob = point_eval::to_blob(&blob_bytes);
    let kzg_commitment = point_eval::blob_to_kzg_commitment(&blob);
    let blob_versioned_hash = b256_from_legacy(&point_eval::get_versioned_hash(&kzg_commitment));
    let challenge_digest = payload.get_challenge_digest(blob_versioned_hash);
    let challenge_scalar = point_eval::get_x_from_challenge(challenge_digest);
    let (_proof, evaluation) = point_eval::get_kzg_proof(&blob, challenge_digest);

    let header = BatchHeaderV6 {
        version: fork.to_protocol_version(),
        batch_index: 99,
        l1_message_popped: 0,
        total_l1_message_popped: 0,
        parent_batch_hash: B256::repeat_byte(0x55),
        last_block_timestamp: block_ctx.timestamp,
        data_hash: keccak256(honest_chunk_info.data_hash.as_slice()),
        blob_versioned_hash,
        blob_data_proof: [
            b256_from_u256(challenge_scalar),
            b256_from_u256(evaluation),
        ],
    };

    let batch_witness = BatchWitness {
        chunk_proofs: vec![chunk_proof.clone()],
        chunk_infos: vec![forged_chunk_info.clone()],
        blob_bytes: blob_bytes.clone(),
        point_eval_witness: None,
        reference_header: ReferenceHeader::V6(header),
        fork_name: fork,
    };

    assert_eq!(chunk_proof.commitment.vm, CHUNK_VM_COMMIT, "sanity: vm commitment must match");
    assert_eq!(chunk_proof.commitment.exe, CHUNK_EXE_COMMIT, "sanity: exe commitment must match");

    let aggregated_chunk_infos: Vec<_> = batch_witness
        .chunk_infos
        .iter()
        .map(|info| (info.clone(), fork))
        .collect();
    let aggregated_chunk_hashes = pi_hashes_from_proofs(batch_witness.chunk_proofs.as_slice());
    validate_aggregated_pi(aggregated_chunk_infos.as_slice(), aggregated_chunk_hashes.as_slice());
    assert_eq!(aggregated_chunk_hashes[0], honest_chunk_pi_hash);

    let batch_info_before_tamper = BatchInfo::from(&batch_witness);
    assert_eq!(batch_info_before_tamper.prev_msg_queue_hash, B256::ZERO);
    assert_eq!(batch_info_before_tamper.post_msg_queue_hash, B256::ZERO);

    let mut forged_batch_info = batch_info_before_tamper.clone();
    forged_batch_info.prev_msg_queue_hash = B256::repeat_byte(0x77);
    forged_batch_info.post_msg_queue_hash = B256::repeat_byte(0x88);

    assert_ne!(
        batch_info_before_tamper.prev_msg_queue_hash,
        forged_batch_info.prev_msg_queue_hash,
        "tampering batch prev queue hash"
    );
    assert_ne!(
        batch_info_before_tamper.post_msg_queue_hash,
        forged_batch_info.post_msg_queue_hash,
        "tampering batch post queue hash"
    );

    let honest_batch_pi_hash = batch_info_before_tamper.pi_hash_by_fork(fork);

    // --- Step 3: forge a bundle witness that aggregates the forged batch.
    let fake_batch_proof = AggregationInput {
        public_values: to_public_values(&honest_batch_pi_hash),
        commitment: ProgramCommitment {
            exe: BATCH_EXE_COMMIT,
            vm: BATCH_VM_COMMIT,
        },
    };

    let bundle_witness = BundleWitness {
        batch_proofs: vec![fake_batch_proof.clone()],
        batch_infos: vec![forged_batch_info.clone()],
        fork_name: fork,
    };

    assert_eq!(
        fake_batch_proof.commitment.vm,
        BATCH_VM_COMMIT,
        "sanity: bundle vm commitment must match"
    );
    assert_eq!(
        fake_batch_proof.commitment.exe,
        BATCH_EXE_COMMIT,
        "sanity: bundle exe commitment must match"
    );

    let aggregated_batch_infos: Vec<_> = bundle_witness
        .batch_infos
        .iter()
        .map(|info| (info.clone(), fork))
        .collect();
    let aggregated_batch_hashes = pi_hashes_from_proofs(bundle_witness.batch_proofs.as_slice());
    validate_aggregated_pi(
        aggregated_batch_infos.as_slice(),
        aggregated_batch_hashes.as_slice(),
    );
    assert_eq!(aggregated_batch_hashes[0], honest_batch_pi_hash);

    let bundle_info = BundleInfo::from(&bundle_witness);
    assert_eq!(bundle_info.msg_queue_hash, forged_batch_info.post_msg_queue_hash);
    assert_ne!(
        bundle_info.msg_queue_hash,
        batch_info_before_tamper.post_msg_queue_hash,
        "bundle info exposes tampered queue hash"
    );

    // Final cross-layer sanity checks tying everything together.
    assert_eq!(aggregated_chunk_hashes[0], honest_chunk_pi_hash);
    assert_eq!(aggregated_batch_hashes[0], honest_batch_pi_hash);
    assert_eq!(bundle_witness.fork_name, fork);
}
