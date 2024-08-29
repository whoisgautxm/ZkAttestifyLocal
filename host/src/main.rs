use chrono::Datelike;
use ethers_core::abi::{encode, Token};
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::types::{Address, Signature, H160, H256, U256};
use ethers_core::utils::{hex, keccak256};
use methods::{ADDRESS_ELF, ADDRESS_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use std::fs;

// Define the structure for the message
#[derive(Debug, Serialize, Deserialize)]
struct Attest {
    version: u16,
    schema: H256,
    recipient: Address,
    time: u64,
    expiration_time: u64,
    revocable: bool,
    ref_uid: H256,
    data: Vec<u8>,
    salt: H256,
}

#[derive(Debug, Serialize, Deserialize)]
struct DateOfBirth {
    day: u8,
    month: u8,
    year: u16,
}

// New structs to deserialize the JSON input
#[derive(Debug, Deserialize)]
struct InputData {
    sig: SignatureData,
    signer: String,
}

#[derive(Debug, Deserialize)]
struct SignatureData {
    domain: DomainData,
    signature: SignatureDetails,
    message: MessageData,
}

#[derive(Debug, Deserialize)]
struct DomainData {
    name: String,
    version: String,
    #[serde(rename = "chainId")]
    chain_id: String,
    #[serde(rename = "verifyingContract")]
    verifying_contract: String,
}

#[derive(Debug, Deserialize)]
struct SignatureDetails {
    r: String,
    s: String,
    v: u8,
}

#[derive(Debug, Deserialize)]
struct MessageData {
    version: u16,
    schema: String,
    recipient: String,
    time: String,
    #[serde(rename = "expirationTime")]
    expiration_time: String,
    revocable: bool,
    #[serde(rename = "refUID")]
    ref_uid: String,
    data: String,
    salt: String,
}

fn domain_separator(domain: &EIP712Domain, type_hash: H256) -> H256 {
    let encoded = encode(&[
        Token::FixedBytes(type_hash.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(domain.name.as_ref().unwrap().as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(domain.version.as_ref().unwrap().as_bytes()).to_vec()),
        Token::Uint(domain.chain_id.unwrap()),
        Token::Address(domain.verifying_contract.unwrap()),
    ]);
    keccak256(&encoded).into()
}

fn calculate_age(dob: &DateOfBirth) -> u8 {
    let now = chrono::Utc::now().date_naive();
    let dob = chrono::NaiveDate::from_ymd_opt(dob.year as i32, dob.month as u32, dob.day as u32)
        .expect("Invalid date of birth");
    let mut age = now.year() - dob.year();

    if now.ordinal() < dob.ordinal() {
        age -= 1;
    }
    age as u8
}

fn prove_address(
    signer_address: &H160,
    signature: &Signature,
    digest: &H256,
    message: &Attest,
    dob: &DateOfBirth,
    threshold_age: &u8,
    current_age: &u8,
    current_timestamp: &i64,
) -> risc0_zkvm::Receipt {
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

    let prover = default_prover();
    prover.prove(env, ADDRESS_ELF).unwrap().receipt
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start_time = Instant::now();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Read and parse the JSON file
    let json_str = fs::read_to_string("/Users/shivanshgupta/Desktop/address/host/src/input.json")?;
    let input_data: InputData = serde_json::from_str(&json_str)?;

    // Extract data from the parsed JSON
    let domain = EIP712Domain {
        name: Some(input_data.sig.domain.name),
        version: Some(input_data.sig.domain.version),
        chain_id: Some(U256::from_dec_str(&input_data.sig.domain.chain_id)?),
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
        data: hex::decode(&input_data.sig.message.data[2..])?,
        salt: input_data.sig.message.salt.parse()?,
    };

    // TODO: Extract DOB from the data field or get it from another source
    let dob = DateOfBirth {
        day: 1,
        month: 1,
        year: 1990,
    };

    let current_age = calculate_age(&dob);
    let current_timestamp = chrono::Utc::now().timestamp();
    let threshold_age: u8 = 18;

    println!("Current timestamp is {:?}", current_timestamp);

    let eip712_domain_typehash: H256 = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
    .into();

    let i_domain_separator = domain_separator(&domain, eip712_domain_typehash);

    let message_typehash: H256 = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
    ).into();

    let encoded_message = encode(&[
        Token::FixedBytes(message_typehash.as_bytes().to_vec()),
        Token::Uint(U256::from(message.version)),
        Token::FixedBytes(message.schema.as_bytes().to_vec()),
        Token::Address(message.recipient),
        Token::Uint(U256::from(message.time)),
        Token::Uint(U256::from(message.expiration_time)),
        Token::Bool(message.revocable),
        Token::FixedBytes(message.ref_uid.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(&message.data).to_vec()),
        Token::FixedBytes(message.salt.as_bytes().to_vec()),
    ]);

    let hashed_message = keccak256(&encoded_message);

    let prefix: [u8; 1] = [0x19];
    let eip712_version: [u8; 1] = [0x01];

    let mut combined = Vec::new();
    combined.extend_from_slice(&prefix);
    combined.extend_from_slice(&eip712_version);
    combined.extend_from_slice(&i_domain_separator.to_fixed_bytes());
    combined.extend_from_slice(&hashed_message);

    let digest = keccak256(&combined).into();

    let signature = Signature {
        r: input_data.sig.signature.r.parse()?,
        s: input_data.sig.signature.s.parse()?,
        v: input_data.sig.signature.v.into(),
    };

    let receipt = prove_address(
        &signer_address,
        &signature,
        &digest,
        &message,
        &dob,
        &threshold_age,
        &current_age,
        &current_timestamp,
    );

    receipt.verify(ADDRESS_ID).unwrap();
    println!("Receipt verified.");

    let (signer_address, signature, message, threshold_age, current_timestamp, hash): (
        H160,
        Signature,
        Attest,
        u8,
        i64,
        H256,
    ) = receipt.journal.decode().unwrap();

    println!(
        "This message {:?} is signed with the signature {:?} using the account address {:?} proofs that the signer is above the age of {:?} at the time {:?} with the hash {:?}",
        message, signature, signer_address, threshold_age, current_timestamp, hash
    );

    let elapsed_time = start_time.elapsed();
    println!("Execution time: {:?}", elapsed_time);

    Ok(())
}