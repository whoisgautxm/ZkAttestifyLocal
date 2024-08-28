use ethers_core::types::{RecoveryMessage, Signature, H160, H256};
use risc0_zkvm::guest::env;

fn main() {
    // Specify types for the tuple
    let (signer_address, signature, digest): (H160, Signature, H256) = env::read();

    let recovery_message = RecoveryMessage::Hash(digest);

    let recovered_address = signature.recover(recovery_message).unwrap();

    // ... rest of your code ...

    if signer_address != recovered_address {
        panic!("Invalid signature");
    }

    println!("Signature is valid");
    env::commit::<(H160, Signature)>(&(signer_address, signature));
    println!("Signature is committed");
}
