mod structs;
mod helper;
mod zk_proof;

use std::fs;
use std::time::Instant;
use ethers_core::types::{H160, H256};
use structs::{InputData, Attest};
use methods::ADDRESS_ID;
use helper::{domain_separator };
use zk_proof::prove_address;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Read and parse the JSON file
    let json_str = fs::read_to_string("./host/src/input.json")?;
    let input_data: InputData = serde_json::from_str(&json_str)?;

    // Extract data from the parsed JSON
    let domain = ethers_core::types::transaction::eip712::EIP712Domain {
        name: Some(input_data.sig.domain.name),
        version: Some(input_data.sig.domain.version),
        chain_id: Some(ethers_core::types::U256::from_dec_str(&input_data.sig.domain.chain_id)?),
        verifying_contract: Some(input_data.sig.domain.verifying_contract.parse()?),
        salt: None,
    };

    let signer_address: H160 = input_data.signer.parse()?;


    let message = Attest {
        version: input_data.sig.message.version,
        schema: input_data.sig.message.schema.parse()?,
        recipient: input_data.sig.message.recipient.parse()?,
        time: input_data.sig.message.time.parse()?,
        expiration_time: input_data.sig.message.expiration_time.parse()?,
        revocable: input_data.sig.message.revocable,
        ref_uid: input_data.sig.message.ref_uid.parse()?,
        data: ethers_core::utils::hex::decode(&input_data.sig.message.data[2..])?,
        salt: input_data.sig.message.salt.parse()?,
    };

    // Calculate the current timestamp and the threshold age
    let current_timestamp = chrono::Utc::now().timestamp() as u64;
    let threshold_age: u64 = 18 * 365 * 24 * 60 * 60; // 18 years in seconds

    // Calculate the domain separator and the message hash
    let domain_separator = domain_separator(&domain, ethers_core::utils::keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    ).into());

    // Parse the signature
    let signature = ethers_core::types::Signature {
        r: input_data.sig.signature.r.parse()?,
        s: input_data.sig.signature.s.parse()?,
        v: input_data.sig.signature.v.into(),
    };

    // Fields which are sent to the guest code
    let receipt = prove_address(
        &signer_address,
        &signature,
        &threshold_age,
        &current_timestamp,
        message,  // Pass the entire Attest struct
        domain_separator,  // Pass the domain separator
    );

    receipt.verify(ADDRESS_ID).unwrap();
    println!("Receipt verified.");

    let (signer_address,  threshold_age, current_timestamp, attest_time, domain_separator): (
        H160,
        u64,
        u64,
        u64,
        H256,
    ) = receipt.journal.decode().unwrap();

    println!("The signer {:?} is verified to be above the age of {:?} on the time of {:?} attestation.", signer_address,threshold_age,current_timestamp);
    println!("The attestation time is {:?}", attest_time);
    println!("The domain separator is {:?}", domain_separator);
    let elapsed_time = start_time.elapsed();
    println!("Execution time: {:?}", elapsed_time);

    Ok(())
}