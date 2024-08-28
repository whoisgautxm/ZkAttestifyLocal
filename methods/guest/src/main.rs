use ethers_core::types::Address;
use ethers_core::types::{RecoveryMessage, Signature, H160, H256};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
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

fn main() {
    let (signer_address, signature, digest, message, dob, threshold_age , current_age , current_timestamp): (
        H160,
        Signature,
        H256,
        Attest,
        DateOfBirth,
        u8,
        u8,
        i64,
    ) = env::read();

    let recovery_message = RecoveryMessage::Hash(digest);
    let recovered_address = signature.recover(recovery_message).unwrap();

    let hash: H256 = keccak256(&[signer_address.as_bytes(), &[current_age]].concat()).into();

    // let current_timestamp = chrono::Utc::now().timestamp();

    if signer_address != recovered_address {
        panic!("Invalid signature");
    } else {
        if current_age < threshold_age {
            panic!("Age is below threshold");
        } else {
            env::commit::<(H160, Signature, Attest,u8,i64,H256)>(&(
                signer_address,
                signature,
                message,
                threshold_age,
                current_timestamp,
                hash,
            ));
        }
    }
}
