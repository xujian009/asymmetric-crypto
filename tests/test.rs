use asymmetric_crypto::{sm2_gen_keypair, sm2_signature, sm2_verify};
use asymmetric_crypto::{KeyPair, Splitable};
use core::convert::AsRef;
use core::fmt::Debug;
use dislog_hal::Bytes;
use hex::{FromHex, FromHexError};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use tiny_keccak::Hasher;
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
        self.0.update(data.as_ref());
    }

    fn finalize(self) -> Self::Output {
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

#[test]
fn test_key_pair_curve25519_gen() {
    let mut rng = thread_rng();

    let info_a = KeyPair::<
        [u8; 32],
        LocalSha3,
        dislog_hal_curve25519::PointInner,
        dislog_hal_curve25519::ScalarInner,
    >::generate::<ThreadRng>(&mut rng)
    .unwrap();

    println!("{:?}", &info_a);

    let data_b = [
        187, 106, 9, 139, 107, 13, 195, 224, 202, 130, 3, 243, 167, 193, 182, 87, 81, 183, 243, 81,
        74, 222, 16, 87, 21, 206, 127, 54, 32, 51, 18, 110,
    ];
    let info_b = KeyPair::<
        [u8; 32],
        LocalSha3,
        dislog_hal_curve25519::PointInner,
        dislog_hal_curve25519::ScalarInner,
    >::generate_from_seed(data_b)
    .unwrap();

    assert_eq!(
        info_b.get_seed(),
        [
            187, 106, 9, 139, 107, 13, 195, 224, 202, 130, 3, 243, 167, 193, 182, 87, 81, 183, 243,
            81, 74, 222, 16, 87, 21, 206, 127, 54, 32, 51, 18, 110
        ]
    );
    assert_eq!(
        info_b.get_secret_key().inner.to_bytes(),
        [
            87, 7, 77, 176, 244, 182, 94, 31, 180, 131, 71, 165, 24, 196, 136, 15, 252, 125, 185,
            230, 56, 228, 42, 161, 117, 43, 81, 248, 50, 5, 246, 13
        ]
    );
    assert_eq!(
        info_b.get_public_key().inner.to_bytes(),
        [
            46, 170, 200, 38, 199, 246, 214, 187, 69, 5, 152, 75, 233, 6, 232, 150, 174, 190, 32,
            251, 147, 169, 7, 163, 11, 84, 164, 36, 35, 57, 2, 96
        ]
    );
    assert_eq!(
        info_b.get_code(),
        [
            79, 186, 168, 34, 234, 151, 58, 38, 129, 202, 119, 36, 57, 47, 200, 150, 111, 180, 230,
            97, 128, 154, 251, 16, 226, 137, 121, 10, 224, 119, 207, 56
        ]
    );
}

#[test]
fn test_key_pair_sm2_gen() {
    let mut rng = thread_rng();

    let info_a = KeyPair::<
        [u8; 32],
        LocalSha3,
        dislog_hal_sm2::PointInner,
        dislog_hal_sm2::ScalarInner,
    >::generate::<ThreadRng>(&mut rng)
    .unwrap();

    println!("test println: {:?}", &info_a);

    let data_b = [
        34, 65, 213, 57, 9, 244, 187, 83, 43, 5, 198, 33, 107, 223, 3, 114, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255,
    ];
    let info_b = KeyPair::<
        [u8; 32],
        LocalSha3,
        dislog_hal_sm2::PointInner,
        dislog_hal_sm2::ScalarInner,
    >::generate_from_seed(data_b)
    .unwrap();

    assert_eq!(
        info_b.get_seed(),
        [
            34, 65, 213, 57, 9, 244, 187, 83, 43, 5, 198, 33, 107, 223, 3, 114, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255
        ]
    );
    assert_eq!(
        info_b.get_secret_key().inner.to_bytes().as_ref(),
        &[
            100, 228, 238, 48, 82, 171, 142, 44, 136, 11, 25, 200, 143, 219, 38, 151, 240, 198,
            203, 172, 209, 197, 254, 44, 122, 177, 156, 57, 38, 227, 43, 111
        ][..]
    );
    assert_eq!(
        info_b.get_public_key().inner.to_bytes().as_ref(),
        &[
            3, 31, 15, 213, 251, 207, 39, 245, 108, 63, 234, 202, 80, 139, 13, 202, 236, 135, 128,
            216, 113, 219, 223, 148, 108, 142, 131, 166, 167, 255, 152, 114, 125
        ][..]
    );
    assert_eq!(
        info_b.get_code(),
        [
            229, 84, 250, 54, 144, 9, 137, 207, 152, 248, 116, 168, 64, 249, 68, 7, 199, 5, 217,
            110, 207, 246, 195, 164, 166, 13, 89, 42, 203, 13, 181, 229
        ]
    );
}

#[test]
fn test_sm2_sigture() {
    let data_b = [
        34, 65, 213, 57, 9, 244, 187, 83, 43, 5, 198, 33, 107, 223, 3, 114, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255,
    ];
    let info_b = sm2_gen_keypair(data_b).unwrap();

    let text = [244, 187, 83, 43, 5, 198, 33];

    let sig_info = sm2_signature(&text[..], &info_b);

    let ans = sm2_verify(&text[..], &info_b.get_public_key(), &sig_info);
    assert_eq!(ans, true);
}
