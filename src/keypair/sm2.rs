use crate::hasher::sha3::Sha3;
use crate::keypair::Keypair;
use crate::{signature, CryptoError};
use dislog_hal::{Hasher, Point, Scalar};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct KeyPairSm2(
    pub Keypair<[u8; 32], Sha3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>,
);

impl crate::prelude::Keypair for KeyPairSm2 {
    type Seed = [u8; 32];

    type Secret = Scalar<dislog_hal_sm2::ScalarInner>;

    type Public = Point<dislog_hal_sm2::PointInner>;

    type Code = [u8; 32];

    type Signature = signature::sm2::Signature<dislog_hal_sm2::ScalarInner>;

    fn generate<R: RngCore>(rng: &mut R) -> Result<Self, CryptoError> {
        match Keypair::generate::<R>(rng) {
            Ok(x) => Ok(Self(x)),
            Err(_) => Err(CryptoError::KeyPairGenError),
        }
    }

    fn generate_from_seed(seed: Self::Seed) -> Result<Self, CryptoError> {
        match Keypair::generate_from_seed(seed) {
            Ok(x) => Ok(Self(x)),
            Err(_) => Err(CryptoError::KeyPairGenError),
        }
    }

    fn sign<H: Default + Hasher<Output = [u8; 32]> + Hasher, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, CryptoError> {
        let mut hasher = H::default();
        hasher.update(msg);
        signature::sm2::sm2_signature::<_, H, _, _, R>(hasher, &self.0.get_secret_key(), rng)
    }

    fn verify<H: Default + Hasher<Output = [u8; 32]> + Hasher>(
        &self,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<bool, CryptoError> {
        let mut hasher = H::default();
        hasher.update(msg);
        Ok(signature::sm2::sm2_verify::<_, H, _, _>(
            hasher,
            &self.0.get_public_key(),
            sig,
        ))
    }
}
