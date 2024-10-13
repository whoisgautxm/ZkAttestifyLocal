// src/zk_proof.rs
// use crate::structs:: DateOfBirth;
use crate::structs::Attest;
use ethers_core::types::Signature;
use ethers_core::types::{H160, H256};
// use methods::ADDRESS_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::path::PathBuf;
use clap::Parser;
use std::fs; // Ensure this is present

#[derive(Parser, Debug)]
pub struct Cli {
  path: PathBuf
}

pub fn prove_address(
    signer_address: &H160,
    signature: &Signature,
    threshold_age: &u64,
    current_timestamp: &u64,
    attest: &Attest,
    domain_separator: H256,
) -> Receipt {
    let args = Cli::parse();
    let ADDRESS_ELF = args.path;
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
    // Read the ELF file into a byte vector
    let elf_bytes = fs::read(&ADDRESS_ELF).expect("Failed to read ELF file");
    prover.prove(env, &elf_bytes).unwrap().receipt // Pass the byte slice
}
