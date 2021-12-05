use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use elgamal::{
    rfc7919_groups::SupportedGroups, ElGamal, ElGamalCiphertext, ElGamalError, ElGamalKeyPair,
    ElGamalPP,
};

fn rerandomise(c: &ElGamalCiphertext) -> Result<ElGamalCiphertext, ElGamalError> {
    let y = BigInt::sample_below(&c.pp.q);
    let c1 = BigInt::mod_pow(&c.c1, &y, &c.pp.p);
    let c2 = BigInt::mod_pow(&c.c2, &y, &c.pp.p);
    Ok(ElGamalCiphertext {
        c1,
        c2,
        pp: c.pp.clone(),
    })
}

fn main() {
    let group_id = SupportedGroups::FFDHE2048;
    let alice_pp = ElGamalPP::generate_from_rfc7919(group_id);
    let alice_key_pair = ElGamalKeyPair::generate(&alice_pp);
    // Only works for the identity
    let message = BigInt::from(1);
    let first_cipher = ElGamal::encrypt(&message, &alice_key_pair.pk).unwrap();
    let second_cipher = rerandomise(&first_cipher).unwrap();
    let first_message_tag = ElGamal::decrypt(&first_cipher, &alice_key_pair.sk).unwrap();
    let second_message_tag = ElGamal::decrypt(&second_cipher, &alice_key_pair.sk).unwrap();
    println!(
        "basic encryption: message: {}, first decryption: {}, second decryption {}",
        message, first_message_tag, second_message_tag
    );
}
