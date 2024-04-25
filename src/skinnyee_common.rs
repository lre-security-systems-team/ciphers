use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use crate::ciphers::skinnyee::SKINNYee;
use crate::matrix::Matrix;
use crate::ciphers::SymmetricCipher;

#[allow(dead_code)]
pub fn fill_random_key_and_tweakey(
    rand: &mut ChaCha8Rng,
    key_and_tweakey: &mut Vec<u8>,
    mask: u8,
) {
    rand.fill_bytes(key_and_tweakey);
    key_and_tweakey.iter_mut().for_each(|it| *it &= mask);
    // Mask the RCi 3-bit word initializer
    key_and_tweakey[24 * 4] &= 0b111;
    // Remove mask the three last unused words
    key_and_tweakey[24 * 4 + 1] = 0;
    key_and_tweakey[24 * 4 + 2] = 0;
    key_and_tweakey[24 * 4 + 3] = 0;
}

#[allow(dead_code)]
pub fn compute_tk_xor_tweakey_difference(
    key_and_tweakey: &Matrix<u8>,
    tk0_difference: &Matrix<u8>,
    tk1_difference: &Matrix<u8>,
    tk2_difference: &Matrix<u8>,
    tk3_difference: &Matrix<u8>,
) -> Matrix<u8> {
    let mut tk_xor_tke0 = key_and_tweakey.clone();

    for i in 0..4 {
        for j in 0..4 {
            tk_xor_tke0[(8 + i, j)] ^= tk0_difference[(i, j)];
            tk_xor_tke0[(12 + i, j)] ^= tk1_difference[(i, j)];
            tk_xor_tke0[(16 + i, j)] ^= tk2_difference[(i, j)];
            tk_xor_tke0[(20 + i, j)] ^= tk3_difference[(i, j)];
        }
    }

    tk_xor_tke0
}

#[allow(dead_code)]
pub fn evaluate_boomerang(
    cipher: &SKINNYee,
    key_and_tweakey: &Matrix<u8>,
    mut p0: Matrix<u8>,
    e0_input_difference: &Matrix<u8>,
    e1_output_difference: &Matrix<u8>,
    tk_xor_tke0: &Matrix<u8>,
    tk_xor_tke1: &Matrix<u8>,
    tk_xor_tke0_xor_tke1: &Matrix<u8>,
) ->  usize {
    let mut p1 = &p0 ^ e0_input_difference;

    cipher.cipher(key_and_tweakey, &mut p0);
    p0 ^= e1_output_difference;
    cipher.decipher(tk_xor_tke1, &mut p0);

    cipher.cipher(tk_xor_tke0, &mut p1);
    p1 ^= e1_output_difference;
    cipher.decipher(tk_xor_tke0_xor_tke1, &mut p1);

    let d_out = &p0 ^ &p1;
    if e0_input_difference == &d_out {
        1usize
    } else {
        0usize
    }
}

#[allow(dead_code)]
pub fn evaluate_differential_characteristic(
    cipher: &SKINNYee,
    key_and_tweakey: &Matrix<u8>,
    mut p0: Matrix<u8>,
    input_difference: &Matrix<u8>,
    output_difference: &Matrix<u8>,
    key_and_tweakey_xor_tweakey_difference: &Matrix<u8>,
) -> usize {
    let mut p1 = &p0 ^ input_difference;
    cipher.cipher(key_and_tweakey, &mut p0);
    cipher.cipher(key_and_tweakey_xor_tweakey_difference, &mut p1);

    let d_out = &p0 ^ &p1;
    if output_difference == &d_out {
        1
    } else {
        0
    }
}