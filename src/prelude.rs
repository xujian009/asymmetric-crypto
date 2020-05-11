use crate::CryptoError;
use core::fmt::Debug;
use dislog_hal::{Bytes, Hasher};
use hex::{FromHex, ToHex};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub trait Splitable {
    type Half: Debug + ToHex + FromHex + PartialEq;

    fn split_finalize(self) -> (Self::Half, Self::Half);
}

pub trait Keypair: Serialize + for<'de> Deserialize<'de> {
    type Seed;

    type Secret;

    type Public;

    type Code;

    type Signature: Serialize + for<'de> Deserialize<'de> + Bytes;

    fn generate<R: RngCore>(rng: &mut R) -> Result<Self, CryptoError>;

    fn generate_from_seed(seed: Self::Seed) -> Result<Self, CryptoError>;

    fn sign<H: Default + Hasher<Output = [u8; 32]> + Hasher, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, CryptoError>;

    fn verify<H: Default + Hasher<Output = [u8; 32]> + Hasher>(
        &self,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<bool, CryptoError>;
}
