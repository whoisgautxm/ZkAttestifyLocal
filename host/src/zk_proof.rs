// src/zk_proof.rs
// use crate::structs:: DateOfBirth;
use crate::structs::Attest;
use ethers_core::types::Signature;
use ethers_core::types::{H160, H256};
use methods::ADDRESS_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

pub fn prove_address(
    signer_address: &H160,
    signature: &Signature,
    threshold_age: &u64,
    current_timestamp: &u64,
    attest: &Attest,
    domain_separator: H256,
) -> Receipt {
    let input: (&H160, &Signature, &u64, &u64, &Attest, H256) = (
        signer_address,
        signature,
        threshold_age,
        current_timestamp,
        attest,
        domain_separator,
    );

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    prover.prove(env, ADDRESS_ELF).unwrap().receipt
}
