mod key_pair_gen;
pub use key_pair_gen::KeyPair;

mod prelude;
pub use prelude::Splitable;

mod sigture;
pub use sigture::{sm2_signature, sm2_verify};

mod hasher;
pub use hasher::{Sha3, Sm3};

#[derive(Debug)]
pub enum CryptoError {
    KeyPairGenError,
    KeyPairUnvaildError,
    Sm2SigtureError,
}
