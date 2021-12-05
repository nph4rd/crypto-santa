use curv::BigInt;
use elgamal::{rfc7919_groups::SupportedGroups, ElGamal, ElGamalKeyPair, ElGamalPP};

fn main() {
    let group_id = SupportedGroups::FFDHE2048;
    let alice_pp = ElGamalPP::generate_from_rfc7919(group_id);
    let alice_key_pair = ElGamalKeyPair::generate(&alice_pp);
    let message = BigInt::from(13);
    let cipher = ElGamal::encrypt(&message, &alice_key_pair.pk).unwrap();
    let message_tag = ElGamal::decrypt(&cipher, &alice_key_pair.sk).unwrap();
    println!(
        "basic encryption: message: {}, decrypted: {}",
        message, message_tag
    );
}
