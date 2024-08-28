use ethers_core::types::Address;
use ethers_core::types::{RecoveryMessage, Signature, H160, H256};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use chrono::Datelike;
use ethers_core::utils::keccak256;
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

fn calculate_age(dob: &DateOfBirth) -> u8 {
    let now = chrono::Utc::now();
    let dob = chrono::NaiveDate::from_ymd(dob.year as i32, dob.month as u32, dob.day as u32);
    let age = now.year() - dob.year();
    if now.month() < dob.month() || (now.month() == dob.month() && now.day() < dob.day()) {
        (age - 1) as u8
    } else {
        age as u8
    }
}

fn main() {
    // Specify types for the tuple
    let (signer_address, signature, digest, message, dob, threshold_age): (
        H160,
        Signature,
        H256,
        Attest,
        DateOfBirth,
        u8,
    ) = env::read();

    let recovery_message = RecoveryMessage::Hash(digest);

    let age = calculate_age(&dob);

    let recovered_address = signature.recover(recovery_message).unwrap();

    let hash: H256 = keccak256(&[signer_address.as_bytes(), &[age]].concat()).into();
    let current_timestamp = chrono::Utc::now().timestamp();

    if signer_address != recovered_address {
        panic!("Invalid signature");
    } else {
        if age < threshold_age {
            panic!("Age is below threshold");
        } else {
            println!("Signature is valid");
            env::commit::<(H160, Signature, Attest,u8,i64,H256)>(&(
                signer_address,
                signature,
                message,
                threshold_age,
                current_timestamp,
                hash,
            ));
            println!("Signature is committed");
        }
    }
}
