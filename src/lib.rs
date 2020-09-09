pub mod hasher;
pub mod keypair;
pub mod signature;

pub mod prelude;
pub use prelude::Splitable;

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

pub struct NewU8129(pub [u8; 129]);

impl Debug for NewU8129 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        let mut info = f.debug_list();
        for i in 0..self.0.len() {
            info.entry(&self.0[i]);
        }
        info.finish()
    }
}

impl PartialEq for NewU8129 {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl FromHex for NewU8129 {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut ret = [0u8; 129];
        for i in 0..129 {
            ret[i] = hex.as_ref()[i];
        }
        Ok(Self(ret))
    }
}

impl AsRef<[u8]> for NewU8129 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub enum CryptoError {
    KeyPairGenError,
    KeyPairUnvaildError,
    Sm2SigtureError,
}
