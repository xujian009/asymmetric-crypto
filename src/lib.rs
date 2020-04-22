mod key_pair_gen;
pub use key_pair_gen::{KeyPair, KeyPairError};

mod prelude;
pub use prelude::Splitable;

mod sigture;
pub use sigture::{sm2_gen_keypair, sm2_signature, sm2_verify};
