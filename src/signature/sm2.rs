use crate::CryptoError;
use crate::NewU864;
use core::convert::AsRef;
use core::fmt::Debug;
use dislog_hal::{Bytes, DisLogPoint, Hasher, Point, Scalar, ScalarNumber};
use hex::{FromHex, ToHex};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature<S: ScalarNumber> {
    #[serde(bound(deserialize = "S: ScalarNumber"))]
    r: Scalar<S>,
    #[serde(bound(deserialize = "S: ScalarNumber"))]
    s: Scalar<S>,
}

impl<S: ScalarNumber> Bytes for Signature<S> {
    type BytesType = NewU864;

    type Error = CryptoError;

    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        assert_eq!(bytes.len(), 64);
        Ok(Self {
            r: Scalar::<S>::from_bytes(&bytes[..32]).unwrap(),
            s: Scalar::<S>::from_bytes(&bytes[32..]).unwrap(),
        })
    }

    fn to_bytes(&self) -> Self::BytesType {
        let mut ret = [0u8; 64];
        ret[..32].clone_from_slice(self.r.to_bytes().as_ref());
        ret[32..].clone_from_slice(self.s.to_bytes().as_ref());
        NewU864(ret)
    }
}

impl<S: ScalarNumber> Signature<S> {
    pub fn get_r(&self) -> Scalar<S> {
        self.r.clone()
    }

    pub fn get_s(&self) -> Scalar<S> {
        self.s.clone()
    }
}

pub fn sm2_signature<
    N: Default + AsRef<[u8]> + Debug + ToHex + FromHex + PartialEq + Clone,
    H: Hasher<Output = N> + Default,
    P: DisLogPoint<Scalar = S> + Bytes,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
    R: RngCore,
>(
    hasher: H,
    pri_key: &Scalar<S>,
    rng: &mut R,
) -> Result<Signature<S>, CryptoError> {
    let digest = hasher.finalize();

    let e = Scalar::<S>::from_bytes(digest.as_ref()).unwrap();

    loop {
        // k = rand()
        // (x_1, y_1) = g^kg
        let k = Scalar::<S>::random(rng);
        let p_1 = &Point::<P>::one() * &k;

        // r = e + x_1
        let r = &e + p_1.get_x();
        if r == Scalar::zero() || &r + &k == Scalar::zero() {
            continue;
        }

        // s = (1 + pri_key)^-1 * (k - r * sk)
        let mut s1 = pri_key + &Scalar::<S>::one();
        s1 = s1.inv();

        let s2_1 = &r * pri_key;

        let s = &s1 * (&k - &s2_1);

        if s == Scalar::zero() {
            return Err(CryptoError::Sm2SigtureError);
        }

        // Output the signature (r, s)
        return Ok(Signature::<S> { r, s });
    }
}

pub fn sm2_verify<
    N: Default + AsRef<[u8]> + Debug + ToHex + FromHex + PartialEq + Clone,
    H: Hasher<Output = N> + Default,
    P: DisLogPoint<Scalar = S> + Bytes,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
>(
    msg_wrapper: &[u8],
    pub_key: &Point<P>,
    sig: &Signature<S>,
) -> bool {
    let mut hasher = H::default();
    hasher.update(msg_wrapper);
    let digest = hasher.finalize();

    let e = Scalar::<S>::from_bytes(digest.as_ref()).unwrap();

    let s = sig.get_s();
    let r = sig.get_r();

    // check r and s
    if sig.get_r() == Scalar::zero() || sig.get_s() == Scalar::zero() {
        return false;
    }

    if &r + &s == Scalar::zero() {
        return false;
    }

    let p_1 = (&s * &Point::<P>::one() + ((r + s) * pub_key)).get_x();

    // check R == r?
    &e + &p_1 == sig.get_r()
}
