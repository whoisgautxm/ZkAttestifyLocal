// src/zk_proof.rs
// use crate::structs:: DateOfBirth;
use ethers_core::types::Signature;
use ethers_core::types::{H160, H256};
use methods::ADDRESS_ELF;
use risc0_zkvm::{ExecutorEnv, Receipt};
// use tracing_subscriber::registry::Data;

pub fn prove_address(
    signer_address: &H160,
    signature: &Signature,
    digest: &H256,
    threshold_age: &u64,
    current_timestamp: &u64,
    data: Vec<u8>,
) -> Receipt {
    let input: (
        &H160,
        &Signature,
        &H256,
        &u64,
        &u64,
        Vec<u8>
    ) = (
        signer_address,
        signature,
        digest,
        threshold_age,
        current_timestamp,
        data,
    );

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = risc0_zkvm::default_prover();
    prover.prove(env, ADDRESS_ELF).unwrap().receipt
}
