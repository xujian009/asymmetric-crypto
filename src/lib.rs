mod key_pair_gen;
pub use key_pair_gen::{KeyPair, Splitable};

use core::convert::AsRef;
use core::fmt::Debug;
use hex::{FromHex, FromHexError};
pub struct NewU864(pub [u8; 64]);

impl Debug for NewU864 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "[{:?}]", &self)
    }
}

impl PartialEq for NewU864 {
    fn eq(&self, other: &Self) -> bool {
        self.0[..32] == other.0[..32] && self.0[32..] == other.0[32..]
    }
}

impl FromHex for NewU864 {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        match <[u8; 64]>::from_hex(hex) {
            Ok(x) => Ok(Self(x)),
            Err(err) => Err(err),
        }
    }
}

impl AsRef<[u8]> for NewU864 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
