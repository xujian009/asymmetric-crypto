use crate::CryptoError;
use core::fmt::Debug;
use dislog_hal::{Bytes, DisLogPoint, Hasher, Point, Scalar, ScalarNumber};
use hex::{FromHex, ToHex};
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct Signature<S: ScalarNumber> {
    r: Scalar<S>,
    s: Scalar<S>,
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
    N: Default + AsRef<[u8]> + AsMut<[u8]> + Sized + Debug + ToHex + FromHex + PartialEq + Clone,
    H2: Hasher<Output = N> + Default,
    P: DisLogPoint<Scalar = S> + Bytes,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
    R: RngCore,
>(
    msg_wrapper: &[u8],
    pri_key: &Scalar<S>,
    rng: &mut R,
) -> Result<Signature<S>, CryptoError> {
    let mut hasher = H2::default();
    hasher.update(msg_wrapper);
    let digest = hasher.finalize();

    let e = Scalar::<S>::from_bytes(digest).unwrap();

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
    N: Default + AsRef<[u8]> + AsMut<[u8]> + Sized + Debug + ToHex + FromHex + PartialEq + Clone,
    H2: Hasher<Output = N> + Default,
    P: DisLogPoint<Scalar = S> + Bytes,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
>(
    msg_wrapper: &[u8],
    pub_key: &Point<P>,
    sig: &Signature<S>,
) -> bool {
    let mut hasher = H2::default();
    hasher.update(msg_wrapper);
    let digest = hasher.finalize();

    let e = Scalar::<S>::from_bytes(digest).unwrap();

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
