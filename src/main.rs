use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use elgamal::{
    rfc7919_groups::SupportedGroups, ElGamal, ElGamalCiphertext, ElGamalError, ElGamalKeyPair,
    ElGamalPP,
};

// Represents a single player.
#[derive(Debug)]
struct Player {
    /// The id of the player.
    id: u8,
    /// Who this player gives a present to.
    gives_to: Option<u8>,
    /// Key-pair in the ElGamal cryptosystem.
    key_pair: Option<ElGamalKeyPair>,
}

/// This struct represents an instance of
/// a secret santa that will be played out.
#[derive(Debug)]
struct SecretSanta {
    /// The vector of players.
    players: Vec<Player>,
}

impl SecretSanta {
    /// Function to build a new instance
    /// of a secret santa game with
    /// `n_players`.
    pub fn new(n_players: usize) -> Self {
        let mut players: Vec<Player> = Vec::new();
        for i in 1..n_players {
            players.push(Player {
                id: i as u8,
                gives_to: None,
                key_pair: None,
            })
        }
        SecretSanta { players }
    }
    /// Function that "triggers" the protocol
    /// creating the random permutation of players
    /// in a "decentralised" way.
    pub fn assign(self) {
        // Build new ElGamal instance
        let group_id = SupportedGroups::FFDHE2048;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let mut vec: Vec<BigInt> = Vec::new();
        for mut p in self.players {
            p.key_pair = Some(ElGamalKeyPair::generate(&pp));
            let m = BigInt::from(1);
            let c = ElGamal::encrypt(&m, &p.key_pair.unwrap().pk).unwrap();
            vec.push(c.c2)
        }
        println!("{:?}", vec);
        // Now each player randomly permutes the vector
        // and reandomises each entry.
    }
}

/// Function that rerandomises a ciohertext. Note that this only works
/// when the message `m` is the identity.
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
    let ss = SecretSanta::new(8);
    ss.assign();
    // ss.ask(1);
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
