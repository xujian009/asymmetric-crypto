use asymmetric_crypto::hasher::{sha3::Sha3, sm3::Sm3};
use asymmetric_crypto::keypair::Keypair;
use asymmetric_crypto::signature::sm2::{sm2_signature, sm2_verify};
use byteorder::{BigEndian, WriteBytesExt};
use core::convert::AsRef;
use dislog_hal::{Hasher, Point};
use rand::rngs::ThreadRng;
use rand::thread_rng;

#[test]
fn test_key_pair_curve25519_gen() {
    let mut rng = thread_rng();

    let info_a = Keypair::<
        [u8; 32],
        Sha3,
        dislog_hal_curve25519::PointInner,
        dislog_hal_curve25519::ScalarInner,
    >::generate::<ThreadRng>(&mut rng)
    .unwrap();

    println!("{:?}", &info_a);

    let data_b = [
        187, 106, 9, 139, 107, 13, 195, 224, 202, 130, 3, 243, 167, 193, 182, 87, 81, 183, 243, 81,
        74, 222, 16, 87, 21, 206, 127, 54, 32, 51, 18, 110,
    ];
    let info_b = Keypair::<
        [u8; 32],
        Sha3,
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
        info_b.get_secret_key().to_bytes(),
        [
            87, 7, 77, 176, 244, 182, 94, 31, 180, 131, 71, 165, 24, 196, 136, 15, 252, 125, 185,
            230, 56, 228, 42, 161, 117, 43, 81, 248, 50, 5, 246, 13
        ]
    );
    assert_eq!(
        info_b.get_public_key().to_bytes(),
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

    let info_a = Keypair::<
        [u8; 32],
        Sha3,
        dislog_hal_sm2::PointInner,
        dislog_hal_sm2::ScalarInner,
    >::generate(&mut rng)
    .unwrap();

    println!("test println: {:?}", &info_a);

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

    assert_eq!(
        info_b.get_seed(),
        [
            34, 65, 213, 57, 9, 244, 187, 83, 43, 5, 198, 33, 107, 223, 3, 114, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255
        ]
    );
    assert_eq!(
        info_b.get_secret_key().to_bytes().as_ref(),
        &[
            100, 228, 238, 48, 82, 171, 142, 44, 136, 11, 25, 200, 143, 219, 38, 151, 240, 198,
            203, 172, 209, 197, 254, 44, 122, 177, 156, 57, 38, 227, 43, 111
        ][..]
    );
    assert_eq!(
        info_b.get_public_key().to_bytes().as_ref(),
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
    let mut rng = thread_rng();
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

    let mut hasher_1: Sm3 = Sm3::default();
    hasher_1.update(&text[..]);
    let sig_info = sm2_signature::<
        [u8; 32],
        Sm3,
        dislog_hal_sm2::PointInner,
        dislog_hal_sm2::ScalarInner,
        ThreadRng,
    >(hasher_1, &info_b.get_secret_key(), &mut rng)
    .unwrap();

    println!("sigture: {:?}", sig_info);

    let mut hasher_2: Sm3 = Sm3::default();
    hasher_2.update(&text[..]);
    let ans = sm2_verify::<[u8; 32], Sm3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>(
        hasher_2,
        &info_b.get_public_key(),
        &sig_info,
    );
    assert_eq!(ans, true);

    let mut text_err = [0u8; 7];
    text_err.copy_from_slice(&Vec::from(&text[..])[..]);
    text_err[0] += 1;

    let mut hasher_2: Sm3 = Sm3::default();
    hasher_2.update(&text_err[..]);
    let ans = sm2_verify::<[u8; 32], Sm3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>(
        hasher_2,
        &info_b.get_public_key(),
        &sig_info,
    );
    assert_eq!(ans, false);
}

fn compat_libsm_hash(msg: &[u8], pub_key: &Point<dislog_hal_sm2::PointInner>) -> [u8; 32] {
    let id = "1234567812345678";
    let mut prepend: Vec<u8> = Vec::new();
    if id.len() * 8 > 65535 {
        panic!("ID is too long.");
    }
    prepend
        .write_u16::<BigEndian>((id.len() * 8) as u16)
        .unwrap();
    for c in id.bytes() {
        prepend.push(c);
    }

    let mut a = dislog_hal_sm2::ECC_CTX.get_a().to_bytes();
    let mut b = dislog_hal_sm2::ECC_CTX.get_b().to_bytes();

    prepend.append(&mut a);
    prepend.append(&mut b);

    let generator = Point::<dislog_hal_sm2::PointInner>::generator();

    let mut x_g = Vec::from(generator.get_x().to_bytes());
    let mut y_g = Vec::from(generator.get_y().to_bytes());
    prepend.append(&mut x_g);
    prepend.append(&mut y_g);

    let mut x_a = Vec::from(pub_key.get_x().to_bytes());
    let mut y_a = Vec::from(pub_key.get_y().to_bytes());
    prepend.append(&mut x_a);
    prepend.append(&mut y_a);

    let mut hasher = Sm3::default();
    hasher.update(&prepend[..]);
    let z_a = hasher.finalize();

    // Z_A = HASH_256(ID_LEN || ID || x_G || y_G || x_A || y_A)

    // e = HASH_256(Z_A || M)

    let mut prepended_msg: Vec<u8> = Vec::new();
    prepended_msg.extend_from_slice(&z_a.as_ref());
    prepended_msg.extend_from_slice(&msg[..]);

    let mut hasher = Sm3::default();
    hasher.update(&prepended_msg[..]);
    hasher.finalize()
}

#[test]
fn test_compat_libsm_sigture() {
    let mut rng = thread_rng();
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

    let msg_wrapper = compat_libsm_hash(&text, &info_b.get_public_key());

    let mut hasher_2: Sm3 = Sm3::default();
    hasher_2.update(&msg_wrapper[..]);
    let sig_info = sm2_signature::<
        [u8; 32],
        Sm3,
        dislog_hal_sm2::PointInner,
        dislog_hal_sm2::ScalarInner,
        ThreadRng,
    >(hasher_2, &info_b.get_secret_key(), &mut rng)
    .unwrap();

    println!("sigture: {:?}", sig_info);

    let mut hasher_2: Sm3 = Sm3::default();
    hasher_2.update(&msg_wrapper[..]);
    let ans = sm2_verify::<[u8; 32], Sm3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>(
        hasher_2,
        &info_b.get_public_key(),
        &sig_info,
    );
    assert_eq!(ans, true);

    let mut msg_wrapper_err = [0u8; 32];
    msg_wrapper_err.copy_from_slice(&Vec::from(&msg_wrapper[..])[..]);
    msg_wrapper_err[0] += 1;

    let mut hasher_2: Sm3 = Sm3::default();
    hasher_2.update(&msg_wrapper_err[..]);
    let ans = sm2_verify::<[u8; 32], Sm3, dislog_hal_sm2::PointInner, dislog_hal_sm2::ScalarInner>(
        hasher_2,
        &info_b.get_public_key(),
        &sig_info,
    );
    assert_eq!(ans, false);
}
