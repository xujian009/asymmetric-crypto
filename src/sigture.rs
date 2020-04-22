use crate::prelude::Splitable;
use crate::{KeyPair, KeyPairError};
use core::fmt::Debug;
use cryptape_sm::sm2::signature::Signature;
use dislog_hal::{Bytes, Point};
use dislog_hal_sm2::PointInner;
use hex::{FromHex, FromHexError};
use lazy_static::*;
use num_bigint::BigUint;
use tiny_keccak::Sha3;

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

pub struct LocalSha3(pub Sha3);

impl Debug for LocalSha3 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "[{:?}]", &self)
    }
}

impl Default for LocalSha3 {
    fn default() -> Self {
        Self(Sha3::v512())
    }
}

impl dislog_hal::Hasher for LocalSha3 {
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

impl Splitable for LocalSha3
where
    LocalSha3: dislog_hal::Hasher,
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

type Sm2_Keypair =
    KeyPair<[u8; 32], LocalSha3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>;

lazy_static! {
    static ref ECC_CTX: cryptape_sm::sm2::ecc::EccCtx = cryptape_sm::sm2::ecc::EccCtx::new();
    static ref SM2_SIG_CTX: cryptape_sm::sm2::signature::SigCtx =
        cryptape_sm::sm2::signature::SigCtx::new();
}

pub fn sm2_gen_keypair(seed: [u8; 32]) -> Result<Sm2_Keypair, KeyPairError> {
    Sm2_Keypair::generate_from_seed(seed)
}

pub fn sm2_signature(msg: &[u8], keypair: &Sm2_Keypair) -> Signature {
    let tmp = keypair.get_secret_key().inner.to_bytes();
    let sm2_pri_key = BigUint::from_bytes_le(&tmp[..]);

    let pub_key = keypair.get_public_key().inner.to_bytes();
    let sm2_pub_key = ECC_CTX.bytes_to_point(&pub_key.as_ref()[..]).unwrap();

    let digest = SM2_SIG_CTX.hash("1234567812345678", &sm2_pub_key, msg);

    SM2_SIG_CTX.sign_raw(&digest[..], &sm2_pri_key)
}

pub fn sm2_verify(msg: &[u8], pub_key: &Point<PointInner>, sig: &Signature) -> bool {
    let sm2_pub_key;
    match ECC_CTX.bytes_to_point(pub_key.inner.to_bytes().as_ref()) {
        Ok(x) => {
            sm2_pub_key = x;
        }
        Err(_) => {
            return false;
        }
    }

    let digest = SM2_SIG_CTX.hash("1234567812345678", &sm2_pub_key, msg);

    SM2_SIG_CTX.verify_raw(&digest[..], &sm2_pub_key, sig)
}
