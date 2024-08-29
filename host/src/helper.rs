// src/helpers.rs
use crate::structs::{Attest, DateOfBirth};
use chrono::Datelike;
use ethers_core::abi::decode;
use ethers_core::abi::ParamType;
use ethers_core::abi::Token;
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::types::{H256, U256};
use ethers_core::utils::keccak256;

pub fn domain_separator(domain: &EIP712Domain, type_hash: H256) -> H256 {
    let encoded = ethers_core::abi::encode(&[
        Token::FixedBytes(type_hash.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(domain.name.as_ref().unwrap().as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(domain.version.as_ref().unwrap().as_bytes()).to_vec()),
        Token::Uint(domain.chain_id.unwrap()),
        Token::Address(domain.verifying_contract.unwrap()),
    ]);
    keccak256(&encoded).into()
}

pub fn calculate_age(dob: &DateOfBirth) -> u8 {
    let now = chrono::Utc::now().date_naive();
    let dob = chrono::NaiveDate::from_ymd_opt(dob.year as i32, dob.month as u32, dob.day as u32)
        .expect("Invalid date of birth");
    let mut age = now.year() - dob.year();

    if now.ordinal() < dob.ordinal() {
        age -= 1;
    }
    age as u8
}

pub fn hash_message(domain_separator: &H256, message: &Attest) -> H256 {
    let message_typehash: H256 = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
    ).into();

    let encoded_message = ethers_core::abi::encode(&[
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

    let mut combined = Vec::new();
    combined.extend_from_slice(&[0x19, 0x01]);
    combined.extend_from_slice(domain_separator.as_bytes());
    combined.extend_from_slice(&hashed_message);

    keccak256(&combined).into()
}

pub fn decode_date_of_birth(data: &Vec<u8>) -> DateOfBirth {
    
    let param_types = vec![
        ParamType::Uint(8),  // day
        ParamType::Uint(8),  // month
        ParamType::Uint(16), // year
    ];

    // Decode the data
    let decoded: Vec<ethers_core::abi::Token> =
        decode(&param_types, &data).expect("Failed to decode data");

    let day = decoded[0].clone().into_uint().expect("Failed to parse day");
    let month = decoded[1]
        .clone()
        .into_uint()
        .expect("Failed to parse month");
    let year = decoded[2]
        .clone()
        .into_uint()
        .expect("Failed to parse year");

    println!("Decoded date of birth: {}-{}-{}", day, month, year);

    DateOfBirth {
        day: day.as_u128() as u8,
        month: month.as_u128() as u8,
        year: year.as_u128() as u16,
    }
}
