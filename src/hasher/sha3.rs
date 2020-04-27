use crate::prelude::Splitable;
use core::fmt::Debug;
use hex::{FromHex, FromHexError};

pub struct NewU864(pub [u8; 64]);

impl Debug for NewU864 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        let mut info = f.debug_list();
        for i in 0..self.0.len() {
            info.entry(&self.0[i]);
        }
        info.finish()
    }
}

impl PartialEq for NewU864 {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
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

pub struct Sha3(pub tiny_keccak::Sha3);

impl Debug for Sha3 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "[{:?}]", &self)
    }
}

impl Default for Sha3 {
    fn default() -> Self {
        Self(tiny_keccak::Sha3::v512())
    }
}

impl dislog_hal::Hasher for Sha3 {
    type Output = NewU864;

    fn update(&mut self, data: impl AsRef<[u8]>) {
        use tiny_keccak::Hasher;

        self.0.update(data.as_ref());
    }

    fn finalize(self) -> Self::Output {
        use tiny_keccak::Hasher;

        let mut output = [0u8; 64];
        self.0.finalize(&mut output);
        NewU864(output)
    }
}

impl Splitable for Sha3
where
    Sha3: dislog_hal::Hasher,
{
    type Half = [u8; 32];

    fn split_finalize(self) -> (Self::Half, Self::Half) {
        use dislog_hal::Hasher;

        let output = self.finalize().0;

        let mut left = [0u8; 32];
        left.clone_from_slice(&output[..32]);
        let mut right = [0u8; 32];
        right.clone_from_slice(&output[32..]);

        (left, right)
    }
}
