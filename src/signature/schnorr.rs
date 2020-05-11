use crate::{
    keypair::{Keypair, SliceN},
    CryptoError, Splitable,
};
use core::convert::AsRef;
use core::fmt::Debug;
use dislog_hal::{Bytes, DisLogPoint, Hasher, Point, Scalar, ScalarNumber};

#[derive(Debug, Clone)]
pub struct Signature<P: DisLogPoint, S: ScalarNumber> {
    r: Point<P>,
    s: Scalar<S>,
}

impl<S: ScalarNumber, P: DisLogPoint> Signature<P, S> {
    pub fn get_r(&self) -> Point<P> {
        self.r.clone()
    }
    pub fn get_s(&self) -> Scalar<S> {
        self.s.clone()
    }
}

pub fn schnorr_signature<
    N: SliceN,
    H: Hasher + Default + Splitable<Half = N>,
    P: DisLogPoint<Scalar = S> + Bytes,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
>(
    hasher: H,
    key_pair: &Keypair<N, H, P, S>,
) -> Result<Signature<P, S>, CryptoError> {
    let digest = hasher.finalize();

    loop {
        let mut hasher = H::default();
        hasher.update(key_pair.get_code().as_ref());
        hasher.update(digest.as_ref());
        let r = Scalar::<S>::from_bytes(hasher.finalize().as_ref()).unwrap();

        let r_ = Point::<P>::one() * &r;
        let mut hasher = H::default();
        hasher.update(&r_.to_bytes().as_ref());
        hasher.update(key_pair.get_public_key().to_bytes().as_ref());
        hasher.update(digest.as_ref());
        let k = Scalar::<S>::from_bytes(hasher.finalize().as_ref()).unwrap();

        // s = k + xe
        let s_ = r + key_pair.get_secret_key() * &k;

        // Output the signature (r, s)
        return Ok(Signature::<P, S> { r: r_, s: s_ });
    }
}

pub fn schnorr_verify<
    N: SliceN,
    H: Hasher + Default + Splitable<Half = N>,
    P: DisLogPoint<Scalar = S> + Bytes,
    S: ScalarNumber<Point = P> + Bytes<BytesType = N>,
>(
    hasher: H,
    pub_key: &Point<P>,
    sig: &Signature<P, S>,
) -> bool {
    let digest = hasher.finalize();

    let r = sig.get_r();
    let s = sig.get_s();

    let mut hasher = H::default();
    hasher.update(r.to_bytes().as_ref());
    hasher.update(pub_key.to_bytes().as_ref());
    hasher.update(digest.as_ref());
    let k = Scalar::<S>::from_bytes(hasher.finalize().as_ref()).unwrap();

    let mut tmp_ary = [0u8; 32];
    tmp_ary[0] = 0x08;
    let scalar_8 = Scalar::<S>::from_bytes(&tmp_ary[..]).unwrap();

    &scalar_8 * s * Point::<P>::one() == &scalar_8 * r + &scalar_8 * k * pub_key
}

#[cfg(test)]
mod tests {
    use super::{schnorr_signature, schnorr_verify};
    use crate::hasher::sha3::Sha3;
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

        let mut hasher_2 = Sha3::default();
        hasher_2.update(&text[..]);
        let sig_info = schnorr_signature(hasher_2, &info_b).unwrap();

        println!("sigture: {:?}", sig_info);

        let mut hasher_2 = Sha3::default();
        hasher_2.update(&text[..]);
        let ans = schnorr_verify(hasher_2, &info_b.get_public_key(), &sig_info);
        assert_eq!(ans, true);

        let mut msg_wrapper_err = [0u8; 7];
        msg_wrapper_err.copy_from_slice(&text[..]);
        msg_wrapper_err[0] += 1;

        let mut hasher_2 = Sha3::default();
        hasher_2.update(&msg_wrapper_err[..]);
        let ans = schnorr_verify(hasher_2, &info_b.get_public_key(), &sig_info);
        assert_eq!(ans, false);
    }
}
