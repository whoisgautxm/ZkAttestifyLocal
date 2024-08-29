// src/zk_proof.rs

use ethers_core::types::{H160, H256};
use risc0_zkvm::{ExecutorEnv, Receipt};
use crate::structs::{Attest, DateOfBirth};
use ethers_core::types::Signature;
use methods::ADDRESS_ELF;

pub fn prove_address(
    signer_address: &H160,
    signature: &Signature,
    digest: &H256,
    message: &Attest,
    dob: &DateOfBirth,
    threshold_age: &u8,
    current_age: &u8,
    current_timestamp: &i64,
) -> Receipt {
    let input: (
        &H160,
        &Signature,
        &H256,
        &Attest,
        &DateOfBirth,
        &u8,
        &u8,
        &i64,
    ) = (
        signer_address,
        signature,
        digest,
        message,
        dob,
        threshold_age,
        current_age,
        current_timestamp,
    );

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    let prover = risc0_zkvm::default_prover();
 prover.prove(env, ADDRESS_ELF).unwrap().receipt
    }