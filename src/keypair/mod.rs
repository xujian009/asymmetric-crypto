pub mod curve25519;
pub mod ed25519;

use crate::prelude::Splitable;
use crate::CryptoError;
use core::fmt::Debug;
use core::marker::PhantomData;
use dislog_hal::{DisLogPoint, Hasher, Point, Scalar, ScalarNumber};
use hex::{FromHex, ToHex};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub trait SliceN:
    Default
    + AsRef<[u8]>
    + Debug
    + ToHex
    + FromHex
    + PartialEq
    + Clone
    + Serialize
    + for<'de> Deserialize<'de>
{
}

impl SliceN for [u8; 32] {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Keypair<
    N: SliceN,
    H: Hasher + Default + Splitable<Half = N>,
    P: DisLogPoint<Scalar = S>,
    S: ScalarNumber<Point = P>,
> {
    #[serde(bound(deserialize = "N: SliceN"))]
    seed: N,
    #[serde(bound(deserialize = "S: ScalarNumber"))]
    secret_key: Scalar<S>,
    #[serde(bound(deserialize = "P: DisLogPoint<Scalar = S>"))]
    public_key: Point<P>,
    #[serde(bound(deserialize = "N: SliceN"))]
    code: N,
    #[serde(skip)]
    _hash: PhantomData<H>,
}

impl<
        N: SliceN + AsMut<[u8]>,
        H: Hasher + Default + Splitable<Half = N>,
        P: DisLogPoint<Scalar = S>,
        S: ScalarNumber<Point = P>,
    > Clone for Keypair<N, H, P, S>
{
    fn clone(&self) -> Self {
        Self {
            seed: self.seed.clone(),
            secret_key: self.secret_key.clone(),
            public_key: self.public_key.clone(),
            code: self.code.clone(),
            _hash: PhantomData,
        }
    }
}

impl<
        N: SliceN + AsMut<[u8]>,
        H: Hasher + Default + Splitable<Half = N>,
        P: DisLogPoint<Scalar = S>,
        S: ScalarNumber<Point = P>,
    > Keypair<N, H, P, S>
{
    pub fn generate<R: RngCore>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut seed = N::default();
        rng.fill_bytes(seed.as_mut());

        match Self::generate_from_seed(seed) {
            Ok(x) => Ok(x),
            Err(_) => Err(CryptoError::KeyPairGenError),
        }
    }
}

impl<
        N: SliceN,
        H: Hasher + Default + Splitable<Half = N>,
        P: DisLogPoint<Scalar = S>,
        S: ScalarNumber<Point = P>,
    > Keypair<N, H, P, S>
{
    pub fn generate_from_seed(seed: N) -> Result<Self, CryptoError> {
        let mut hasher = H::default();
        hasher.update(seed.as_ref());
        let (secret_key_x, code) = hasher.split_finalize();

        let secret_key = match Scalar::<S>::from_bytes(secret_key_x.as_ref()) {
            Ok(secret_key) => secret_key,
            Err(_) => return Err(CryptoError::KeyPairGenError),
        };

        if secret_key == Scalar::<S>::zero() {
            return Err(CryptoError::KeyPairGenError);
        }

        Ok(Self {
            seed,
            public_key: Point::<P>::generator() * &secret_key,
            secret_key,
            code,
            _hash: PhantomData,
        })
    }

    pub fn get_seed(&self) -> N {
        self.seed.clone()
    }

    pub fn get_secret_key(&self) -> Scalar<S> {
        self.secret_key.clone()
    }

    pub fn get_public_key(&self) -> Point<P> {
        self.public_key.clone()
    }

    pub fn get_code(&self) -> N {
        self.code.clone()
    }
}
