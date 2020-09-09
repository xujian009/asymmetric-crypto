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

pub trait Keypair: Default + Bytes + Debug + Clone + Serialize + for<'de> Deserialize<'de> {
    type Seed;

    type Secret;

    type Public;

    type Code;

    type Signature: Serialize + for<'de> Deserialize<'de> + Bytes;

    type Certificate: Certificate;

    fn generate<R: RngCore>(rng: &mut R) -> Result<Self, CryptoError>;

    fn generate_from_seed(seed: Self::Seed) -> Result<Self, CryptoError>;

    fn sign<H: Default + Hasher<Output = [u8; 32]> + Hasher, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, CryptoError>;

    fn get_certificate(&self) -> Self::Certificate;
}

pub trait Certificate: Default + Serialize + for<'de> Deserialize<'de> + Bytes {
    type Signature;

    fn verify<H: Default + Hasher<Output = [u8; 32]> + Hasher>(
        &self,
        msg: &[u8],
        signature: &Self::Signature,
    ) -> bool;
}
