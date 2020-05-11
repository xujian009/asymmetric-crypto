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

pub fn ecdsa_signature<
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

    // 实际上Scalar::<S>转换不可能抛出错误
    let e = Scalar::<S>::from_bytes(digest.as_ref()).unwrap();

    loop {
        let k = Scalar::<S>::random(rng);

        if k == Scalar::<S>::zero() {
            continue;
        }

        let r = (Point::<P>::one() * &k).get_x();

        let mut s = &e + &r * pri_key;

        if r == Scalar::<S>::zero() || s == Scalar::zero() {
            continue;
        }

        s = k.inv() * s;

        return Ok(Signature::<S> { r, s });
    }
}

pub fn ecdsa_verify<
    N: Default + AsRef<[u8]> + Debug + ToHex + FromHex + PartialEq + Clone,
    H: Hasher<Output = N> + Default,
    P: DisLogPoint<Scalar = S> + Bytes,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
>(
    hasher: H,
    pub_key: &Point<P>,
    sig: &Signature<S>,
) -> bool {
    let digest = hasher.finalize();

    // 实际上Scalar::<S>转换不可能抛出错误
    let e = Scalar::<S>::from_bytes(digest.as_ref()).unwrap();

    let r = sig.get_r();
    let s = sig.get_s();

    let p = s.inv() * e * Point::<P>::one() + s.inv() * &r * pub_key;

    // check R == r?
    r == p.get_x()
}

#[cfg(test)]
mod tests {
    use super::{ecdsa_signature, ecdsa_verify};
    use crate::hasher::{sha3::Sha3, sm3::Sm3};
    use crate::keypair::Keypair;
    use dislog_hal::Hasher;

    #[test]
    fn it_works() {
        let data_b = [
            34, 65, 213, 57, 9, 244, 187, 83, 43, 5, 198, 33, 107, 223, 3, 114, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255,
        ];
        let info_b = Keypair::<
            [u8; 32],
            Sha3,
            dislog_hal_sm2::PointInner,
            dislog_hal_sm2::ScalarInner,
        >::generate_from_seed(data_b)
        .unwrap();

        let text = [244, 187, 83, 43, 5, 198, 33];
        let mut rng = rand::thread_rng();

        let mut hasher_2 = Sm3::default();
        hasher_2.update(&text[..]);
        let sig_info = ecdsa_signature::<
            [u8; 32],
            Sm3,
            dislog_hal_sm2::PointInner,
            dislog_hal_sm2::ScalarInner,
            _,
        >(hasher_2, &info_b.get_secret_key(), &mut rng)
        .unwrap();

        println!("sigture: {:?}", sig_info);

        let mut hasher_2 = Sm3::default();
        hasher_2.update(&text[..]);
        let ans = ecdsa_verify(hasher_2, &info_b.get_public_key(), &sig_info);
        assert_eq!(ans, true);

        let mut msg_wrapper_err = [0u8; 7];
        msg_wrapper_err.copy_from_slice(&text[..]);
        msg_wrapper_err[0] += 1;

        let mut hasher_2 = Sm3::default();
        hasher_2.update(&msg_wrapper_err[..]);
        let ans = ecdsa_verify(hasher_2, &info_b.get_public_key(), &sig_info);
        assert_eq!(ans, false);
    }
}
