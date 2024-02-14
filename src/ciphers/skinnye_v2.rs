use std::mem::swap;
use crate::ciphers::SymmetricCipher;
use crate::lfsr::{LFSR, x};
use crate::matrix::Matrix;

const SKINNY_64_SBOX: [u8; 16] = [
    12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15
];

const RC: [u8; 62] = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33,
    0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B,
    0x17, 0x2E, 0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A, 0x34, 0x29,
    0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13, 0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a,
    0x15, 0x2a, 0x14, 0x28, 0x10, 0x20
];


const NR: [usize; 4] = [32, 36, 40, 44];

const PT: [usize; 16] = [
    9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7
];


#[allow(non_camel_case_types)]
pub struct SKINNYe_v2 {
    r: Option<usize>,
    lfsrs: Vec<LFSR<4>>,
}

impl SKINNYe_v2 {
    pub fn default() -> SKINNYe_v2 {
        SKINNYe_v2 {
            r: None,
            lfsrs: vec![
                LFSR::new([x(2), x(1), x(0), x(3) ^ x(2)]),
                LFSR::new([x(0) ^ x(3), x(3), x(2), x(1)]),
                LFSR::new([x(1), x(0), x(3) ^ x(2), x(2) ^ x(1)]),
            ],
        }
    }

    fn nr(&self, tk: usize) -> usize {
        self.r.unwrap_or(NR[tk - 1])
    }

    fn key_schedule(&self, key: &Matrix<u8>, tk: usize) -> Vec<Vec<Matrix<u8>>> {
        let flattened_tk = key.values
            .chunks(16)
            .collect::<Vec<_>>();
        let mut round_tweakey = flattened_tk.iter()
            .map(|sub_key| {
                Matrix::new(4, 4, sub_key.to_vec())
            }).collect::<Vec<_>>();
        round_tweakey.insert(0, Matrix::empty());
        let mut round_tweakeys = Vec::with_capacity(self.nr(tk));
        round_tweakeys.push(round_tweakey.clone());
        for _ in 1..=self.nr(tk) {
            for z in 1..=tk {
                let flattened_tk = &round_tweakey[z].values;
                let permuted = (0..16)
                    .map(|idx| flattened_tk[PT[idx]])
                    .collect::<Vec<_>>();
                round_tweakey[z] = Matrix::new(4, 4, permuted);
            }
            for z in 2..=tk {
                for i in 0..2 {
                    for j in 0..4 {
                        round_tweakey[z][(i, j)] = self.lfsr(z, round_tweakey[z][(i, j)]);
                    }
                }
            }
            round_tweakeys.push(round_tweakey.clone());
        }
        round_tweakeys
    }

    fn lfsr(&self, i: usize, value: u8) -> u8 {
        self.lfsrs[i - 2].eval(value as usize) as u8
    }

    fn add_round_tweak_key(&self, internal_state: &mut Matrix<u8>, round_tweak_key: &Vec<Matrix<u8>>, tk: usize) {
        match tk {
            1 => {
                for i in 0..=1 {
                    for j in 0..4 {
                        internal_state[(i, j)] ^= round_tweak_key[1][(i, j)];
                    }
                }
            }
            2 => {
                for i in 0..=1 {
                    for j in 0..4 {
                        internal_state[(i, j)] ^= round_tweak_key[1][(i, j)] ^ round_tweak_key[2][(i, j)];
                    }
                }
            }
            3 => {
                for i in 0..=1 {
                    for j in 0..4 {
                        internal_state[(i, j)] ^= round_tweak_key[1][(i, j)] ^ round_tweak_key[2][(i, j)] ^ round_tweak_key[3][(i, j)];
                    }
                }
            }
            4 => {
                for i in 0..=1 {
                    for j in 0..4 {
                        internal_state[(i, j)] ^= round_tweak_key[1][(i, j)] ^ round_tweak_key[2][(i, j)] ^ round_tweak_key[3][(i, j)] ^ round_tweak_key[4][(i, j)];
                    }
                }
            }
            _ => panic!("Invalid tweak_key size: {}", round_tweak_key.len())
        }
    }

    fn add_constants(&self, internal_state: &mut Matrix<u8>, r: usize) {
        let rc = RC[r];
        let c0 = rc & 0xF;
        let c1 = rc >> 4;
        let c2 = 0x02;
        internal_state[(0, 0)] ^= c0;
        internal_state[(1, 0)] ^= c1;
        internal_state[(2, 0)] ^= c2;
    }

    fn sub_cells(&self, internal_state: &mut Matrix<u8>) {
        internal_state.iter_mut()
            .for_each(|it| *it = SKINNY_64_SBOX[*it as usize])
    }

    fn shift_rows(&self, internal_state: &mut Matrix<u8>) {
        let mut copy = internal_state.clone();
        for row in 1..4 {
            for col in 0..4 {
                copy[(row, col)] = internal_state[(row, (col + 4 - row) % 4)];
            }
        }
        swap(&mut copy, internal_state);
    }

    fn mix_columns(&self, internal_state: &mut Matrix<u8>) {
        let mut mix1 = vec![0; 4];
        for j in 0..4 {
            mix1[j] = internal_state[(1, j)] ^ internal_state[(2, j)];
        }
        let mut mix2 = vec![0; 4];
        for j in 0..4 {
            mix2[j] = internal_state[(0, j)] ^ internal_state[(2, j)];
        }
        let mut mix3 = vec![0; 4];
        for j in 0..4 {
            mix3[j] = internal_state[(3, j)] ^ mix2[j];
        }
        for j in 0..4 {
            internal_state[(1, j)] = internal_state[(0, j)];
            internal_state[(0, j)] = mix3[j];
            internal_state[(2, j)] = mix1[j];
            internal_state[(3, j)] = mix2[j];
        }
    }
}

impl SymmetricCipher<Matrix<u8>, Matrix<u8>> for SKINNYe_v2 {
    fn cipher(&self, key: &Matrix<u8>, plaintext: &mut Matrix<u8>) {
        let tk = key.values.len() / plaintext.values.len();
        assert!(tk == 1 || tk == 2 || tk == 3 || tk == 4);
        let round_tweak_keys = self.key_schedule(key, tk);
        for round_num in 0..self.nr(tk) {
            self.sub_cells(plaintext);
            self.add_constants(plaintext, round_num);
            self.add_round_tweak_key(plaintext, &round_tweak_keys[round_num], tk);
            self.shift_rows(plaintext);
            self.mix_columns(plaintext);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphers::skinnye_v2::SKINNYe_v2;
    use crate::ciphers::SymmetricCipher;
    use crate::matrix::Matrix;

    fn parse_nibbles(word: &'static str) -> Vec<u8> {
        fn parse_digit(c: char) -> u8 {
            c.to_digit(16).unwrap() as u8
        }

        word.chars().map(parse_digit).collect()
    }

    #[test]
    fn test_vector_skinnye_v2_64() {
        let skinny = SKINNYe_v2::default();
        let key = Matrix::new(1, 16, parse_nibbles("f5269826fc681238"));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("06034f957724d19d"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("bb39dfb2429b8ac7"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinnye_v2_128() {
        let skinny = SKINNYe_v2::default();
        let key = Matrix::new(2, 16, parse_nibbles("9eb93640d088da6376a39d1c8bea71e1"));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("cf16cfe8fd0f98aa"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("6ceda1f43de92b9e"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinnye_v2_192() {
        let skinny = SKINNYe_v2::default();
        let key = Matrix::new(3, 16, parse_nibbles("ed00c85b120d68618753e24bfd908f60b2dbb41b422dfcd0"));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("530c61d35e8663c3"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("dd2cf1a8f330303c"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinnye_v2_256() {
        // WARN: this test vector is not provided by the cipher authors.
        let skinny = SKINNYe_v2::default();
        let key = Matrix::new(4, 16, parse_nibbles("ed00c85b120d68618753e24bfd908f60b2dbb41b422dfcd0ed00c85b120d6861"));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("530c61d35e8663c3"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("f740f34ebd1430a8"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }
}