use crate::prelude::Splitable;
use core::fmt::Debug;
use core::marker::PhantomData;
use dislog_hal::{Bytes, DisLogPoint, Hasher, Point, Scalar, ScalarNumber};
use hex::{FromHex, ToHex};
use rand::RngCore;

#[derive(Debug)]
pub enum KeyPairError {
    GenError,
}

#[derive(Debug)]
pub struct KeyPair<
    N: Default + AsRef<[u8]> + AsMut<[u8]> + Sized + Debug + ToHex + FromHex + PartialEq + Clone,
    H: Hasher + Default + Splitable<Half = N>,
    P: DisLogPoint<Scalar = S>,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
> {
    seed: N,
    secret_key: Scalar<S>,
    public_key: Point<P>,
    code: N,
    _hash: PhantomData<H>,
}

impl<
        N: Default + AsRef<[u8]> + AsMut<[u8]> + Sized + Debug + ToHex + FromHex + PartialEq + Clone,
        H: Hasher + Default + Splitable<Half = N>,
        P: DisLogPoint<Scalar = S>,
        S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
    > KeyPair<N, H, P, S>
{
    pub fn generate<R: RngCore>(rng: &mut R) -> Result<Self, KeyPairError> {
        let mut seed = N::default();
        rng.fill_bytes(seed.as_mut());

        match Self::generate_from_seed(seed) {
            Ok(x) => Ok(x),
            Err(_) => Err(KeyPairError::GenError),
        }
    }

    pub fn generate_from_seed(seed: N) -> Result<Self, KeyPairError> {
        let mut hasher = H::default();
        hasher.update(seed.as_ref());
        let (secret_key_x, code) = hasher.split_finalize();

        let secret_key;
        match S::from_bytes(secret_key_x) {
            Ok(x) => {
                secret_key = Scalar { inner: x };
            }
            Err(_) => return Err(KeyPairError::GenError),
        }

        if secret_key.inner == S::zero() {
            return Err(KeyPairError::GenError);
        }

        Ok(Self {
            seed,
            public_key: Point {
                inner: P::generator(),
            } * &secret_key,
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
