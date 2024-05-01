use std::mem::swap;

use crate::ciphers::SymmetricCipher;
use crate::lfsr::{LFSR, x};
use crate::matrix::Matrix;

const SKINNY_64_SBOX: [u8; 16] = [
    12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15
];

const INV_SKINNY_64_SBOX: [u8; 16] = [
    3, 4, 6, 8, 12, 10, 1, 14, 9, 2, 5, 7, 0, 11, 13, 15
];

const TK: usize = 4;

const NR: usize = 56;

const PT: [usize; 16] = [
    9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7
];

const INV_PT: [usize; 16] = [
    8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1
];

#[allow(non_camel_case_types)]
pub struct SKINNYee {
    r: Option<usize>,
    lfsrs: Vec<LFSR<4>>,
    inv_lfsrs: Vec<LFSR<4>>,
    rc_lfsr: LFSR<10>,
}

impl SKINNYee {
    #[allow(dead_code)]
    pub fn default() -> SKINNYee {
        SKINNYee {
            r: Some(NR),
            lfsrs: vec![
                LFSR::new([x(2), x(1), x(0), x(3) ^ x(2)]),
                LFSR::new([x(0) ^ x(3), x(3), x(2), x(1)]),
                LFSR::new([x(1), x(0), x(3) ^ x(2), x(2) ^ x(1)]),
            ],
            inv_lfsrs: vec![
                LFSR::new([x(3) ^ x(0), x(3), x(2), x(1)]),
                LFSR::new([x(2), x(1), x(0), x(3) ^ x(2)]),
                LFSR::new([x(1) ^ x(0) ^ x(3), x(0) ^ x(3), x(3), x(2)]),
            ],
            rc_lfsr: LFSR::new([
                x(8), x(7), x(6), x(5), x(4), x(3), x(2), x(1), x(0), x(9) ^ x(3) ^ x(2) ^ x(0)
            ]),
        }
    }

    #[allow(dead_code)]
    pub fn with_rounds(r: usize) -> SKINNYee {
        SKINNYee {
            r: Some(r),
            lfsrs: vec![
                LFSR::new([x(2), x(1), x(0), x(3) ^ x(2)]),
                LFSR::new([x(0) ^ x(3), x(3), x(2), x(1)]),
                LFSR::new([x(1), x(0), x(3) ^ x(2), x(2) ^ x(1)]),
            ],
            inv_lfsrs: vec![
                LFSR::new([x(3) ^ x(0), x(3), x(2), x(1)]),
                LFSR::new([x(2), x(1), x(0), x(3) ^ x(2)]),
                LFSR::new([x(1) ^ x(0) ^ x(3), x(0) ^ x(3), x(3), x(2)]),
            ],
            rc_lfsr: LFSR::new([
                x(8), x(7), x(6), x(5), x(4), x(3), x(2), x(1), x(0), x(9) ^ x(3) ^ x(2) ^ x(0)
            ]),
        }
    }

    #[inline]
    fn nr(&self) -> usize {
        self.r.unwrap_or(NR)
    }

    #[inline]
    fn nr_tweak_key_schedule(&self, key: &Matrix<u8>, nr: usize) -> Vec<Vec<Matrix<u8>>> {
        let mut round_tweakey = key.values
            .chunks(16)
            .map(|sub_key| {
                Matrix::new(4, 4, sub_key.to_vec())
            }).collect::<Vec<_>>();
        round_tweakey.insert(0, Matrix::empty());
        let mut round_tweakeys = Vec::with_capacity(nr + 1);
        round_tweakeys.push(round_tweakey.clone());
        let mut permuted = vec![0; 16];
        for _ in 1..=nr {
            for z in 1..=TK {
                let flattened_tk = &round_tweakey[z].values;
                for idx in 0..16 {
                    permuted[idx] = flattened_tk[PT[idx]]
                }
                swap(&mut round_tweakey[z].values, &mut permuted);
            }
            for z in 2..=TK {
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

    #[inline]
    #[allow(dead_code)]
    pub fn inv_nr_tweak_key_schedule(&self, key: &Matrix<u8>, nr: usize) -> Vec<Vec<Matrix<u8>>> {
        let mut round_tweakey = key.values
            .chunks(16)
            .map(|sub_key| {
                Matrix::new(4, 4, sub_key.to_vec())
            }).collect::<Vec<_>>();
        round_tweakey.insert(0, Matrix::empty());
        let mut round_tweakeys = Vec::with_capacity(nr + 1);
        round_tweakeys.push(round_tweakey.clone());
        let mut permuted = vec![0; 16];
        for _ in 1..=nr {
            for z in 2..=TK {
                for i in 0..2 {
                    for j in 0..4 {
                        round_tweakey[z][(i, j)] = self.inv_lfsr(z, round_tweakey[z][(i, j)]);
                    }
                }
            }
            for z in 1..=TK {
                let flattened_tk = &round_tweakey[z].values;
                for idx in 0..16 {
                    permuted[idx] = flattened_tk[INV_PT[idx]]
                }
                swap(&mut round_tweakey[z].values, &mut permuted);
            }
            round_tweakeys.push(round_tweakey.clone());
        }
        round_tweakeys
    }

    #[inline]
    fn tweak_key_schedule(&self, key: &Matrix<u8>) -> Vec<Vec<Matrix<u8>>> {
        self.nr_tweak_key_schedule(key, self.nr())
    }

    #[inline]
    fn lfsr(&self, i: usize, value: u8) -> u8 {
        self.lfsrs[i - 2].eval(value as usize) as u8
    }

    #[inline]
    fn inv_lfsr(&self, i: usize, value: u8) -> u8 {
        self.inv_lfsrs[i - 2].eval(value as usize) as u8
    }

    #[inline]
    fn add_round_key(&self, internal_state: &mut Matrix<u8>, round_tweak_key: &Vec<Matrix<u8>>, key: &Matrix<u8>) {
        for i in 0..=1 {
            for j in 0..4 {
                internal_state[(i, j)] ^= (1..=TK).fold(0, |acc, z| acc ^ round_tweak_key[z][(i, j)]);
            }
        }
        for i in 2..=3 {
            for j in 0..4 {
                internal_state[(i, j)] ^= key[(i - 2, j)];
            }
        }
    }

    #[inline]
    fn add_constants(&self, internal_state: &mut Matrix<u8>, rc: &Matrix<u8>) {
        for i in 0..4 {
            for j in 0..4 {
                internal_state[(i, j)] ^= rc[(i, j)];
            }
        }
    }

    #[inline]
    fn sub_cells(&self, internal_state: &mut Matrix<u8>) {
        internal_state.iter_mut()
            .for_each(|it| *it = SKINNY_64_SBOX[*it as usize])
    }

    #[inline]
    fn inv_sub_cells(&self, internal_state: &mut Matrix<u8>) {
        internal_state.iter_mut()
            .for_each(|it| *it = INV_SKINNY_64_SBOX[*it as usize])
    }


    #[inline]
    fn shift_rows(&self, internal_state: &mut Matrix<u8>) {
        let mut copy = internal_state.clone();
        for row in 1..4 {
            for col in 0..4 {
                copy[(row, col)] = internal_state[(row, (col + 4 - row) % 4)];
            }
        }
        swap(&mut copy, internal_state);
    }

    #[inline]
    fn inv_shift_rows(&self, internal_state: &mut Matrix<u8>) {
        let mut copy = internal_state.clone();
        for row in 1..4 {
            for col in 0..4 {
                copy[(row, (col + 4 - row) % 4)] = internal_state[(row, col)];
            }
        }
        swap(&mut copy, internal_state);
    }

    #[inline]
    pub fn mix_columns(&self, internal_state: &mut Matrix<u8>) {
        let mut tmp: u8;
        for j in 0..4 {
            internal_state[(1, j)] ^= internal_state[(2, j)];
            internal_state[(2, j)] ^= internal_state[(0, j)];
            internal_state[(3, j)] ^= internal_state[(2, j)];

            tmp = internal_state[(3, j)];
            internal_state[(3, j)] = internal_state[(2, j)];
            internal_state[(2, j)] = internal_state[(1, j)];
            internal_state[(1, j)] = internal_state[(0, j)];
            internal_state[(0, j)] = tmp;
        }
    }

    #[inline]
    pub fn inv_mix_columns(&self, internal_state: &mut Matrix<u8>) {
        let mut tmp: u8;
        for j in 0..4 {
            internal_state[(0, j)] ^= internal_state[(3, j)]; // A <- A xor B
            internal_state[(3, j)] ^= internal_state[(1, j)]; // D <- D xor B
            internal_state[(2, j)] ^= internal_state[(3, j)]; // C <- C xor D xor B

            tmp = internal_state[(0, j)];
            internal_state[(0, j)] = internal_state[(1, j)];
            internal_state[(1, j)] = internal_state[(2, j)];
            internal_state[(2, j)] = internal_state[(3, j)];
            internal_state[(3, j)] = tmp;
        }
    }

    pub fn split_key(&self, full_key: &Matrix<u8>) -> (Vec<Matrix<u8>>, Matrix<u8>, u16) {
        // Data representation
        // K0  n000 n001 n002 n003
        //     n010 n011 n012 n013
        //     ---------------
        // K1  n020 n021 n022 n023
        //     n030 n031 n032 n033
        //     ---------------
        // K2  n040 n041 n042 n043
        //     n050 n051 n052 n053
        //     ---------------
        // K3  n060 n061 n062 n063
        //     n070 n071 n072 n073
        //     ---------------
        // TK1 n080 n081 n082 n083
        //     n090 n091 n092 n093
        //     n100 n101 n102 n103
        //     n110 n111 n112 n113
        //     ---------------
        // TK2 n120 n121 n122 n123
        //     n130 n131 n132 n133
        //     n140 n141 n142 n143
        //     n150 n151 n152 n153
        //     ---------------
        // TK3 n160 n161 n162 n163
        //     n170 n171 n172 n173
        //     n180 n181 n182 n183
        //     n190 n191 n192 n193
        //     ---------------
        // TK4 n200 n201 n202 n203
        //     n210 n211 n212 n213
        //     n220 n221 n222 n223
        //     n230 n231 n232 n233
        //     ---------------
        // RCi n240 xxxx xxxx xxxx

        let mut sub_keys = Vec::with_capacity(4);
        // Four K_i of 2 by 4 nibbles
        for key_no in 0..4 {
            let mut sub_key_values = Vec::with_capacity(2 * 4);
            for row in 0..2 {
                for col in 0..4 {
                    sub_key_values.push(full_key[(key_no * 2 + row, col)])
                }
            }
            let sub_key = Matrix::new(2, 4, sub_key_values);
            sub_keys.push(sub_key);
        }

        // Four TK of 4 by 4 nibbles
        let mut tweak_key_values = Vec::with_capacity(4 * 4 * 4);
        for tk in 0..4 {
            for row in 0..4 {
                for col in 0..4 {
                    tweak_key_values.push(full_key[(8 + tk * 4 + row, col)])
                }
            }
        }
        let tweak_key = Matrix::new(16, 4, tweak_key_values);
        let mut rc_init = full_key[(24, 0)] as u16;
        assert!(rc_init <= 0b111);
        rc_init = (rc_init << 7) | 1;
        (sub_keys, tweak_key, rc_init)
    }

    fn generate_constants(&self, rc_init: u16) -> Vec<Matrix<u8>> {
        let mut round_constants = Vec::with_capacity(self.nr());
        let mut rci = rc_init;
        for _ in 0..self.nr() {
            let mut current_round_constants = Vec::with_capacity(16);
            for _ in 0..4 {
                for _ in 0..4 {
                    current_round_constants.push((rci & 0xF) as u8);
                    rci = self.rc_lfsr.eval(rci as usize) as u16;
                }
            }
            round_constants.push(Matrix::new(4, 4, current_round_constants));
        }
        round_constants
    }
}

impl SymmetricCipher<Matrix<u8>, Matrix<u8>> for SKINNYee {
    fn cipher(&self, key: &Matrix<u8>, plaintext: &mut Matrix<u8>) {
        let (key, tweak, rc_init) = self.split_key(key);
        let round_tweak_keys = self.tweak_key_schedule(&tweak);
        let rc = self.generate_constants(rc_init);
        for round_num in 0..self.nr() {
            self.sub_cells(plaintext);
            self.add_constants(plaintext, &rc[round_num]);
            self.add_round_key(plaintext, &round_tweak_keys[round_num], &key[round_num % 4]);
            self.shift_rows(plaintext);
            self.mix_columns(plaintext);
        }
    }

    fn decipher(&self, key: &Matrix<u8>, plaintext: &mut Matrix<u8>) {
        let (key, tweak, rc_init) = self.split_key(key);
        let round_tweak_keys = self.tweak_key_schedule(&tweak);
        let rc = self.generate_constants(rc_init);
        for round_num in (0..self.nr()).rev() {
            self.inv_mix_columns(plaintext);
            self.inv_shift_rows(plaintext);
            self.add_round_key(plaintext, &round_tweak_keys[round_num], &key[round_num % 4]);
            self.add_constants(plaintext, &rc[round_num]);
            self.inv_sub_cells(plaintext);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphers::skinnyee::SKINNYee;
    use crate::ciphers::SymmetricCipher;
    use crate::matrix::Matrix;

    fn parse_nibbles(word: &'static str) -> Vec<u8> {
        fn parse_digit(c: char) -> Option<u8> {
            if c.is_whitespace() {
                None
            } else {
                Some(c.to_digit(16).unwrap() as u8)
            }
        }

        word.chars().filter_map(parse_digit).collect()
    }

    #[test]
    fn test_vector_skinnyee() {
        let skinny = SKINNYee::default();
        let key = Matrix::new(25, 4, parse_nibbles("\
        aaaaaaaa\
        bbbbbbbb\
        cccccccc\
        dddddddd\
        0000000000000000\
        1111111111111111\
        2222222222222222\
        3333333333333333\
        1000
        "));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("06034f957724d19d"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("4510c411d8877458"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_decipher_skinnyee() {
        let skinny = SKINNYee::default();
        let key = Matrix::new(25, 4, parse_nibbles("\
        aaaaaaaa\
        bbbbbbbb\
        cccccccc\
        dddddddd\
        0000000000000000\
        1111111111111111\
        2222222222222222\
        3333333333333333\
        1000
        "));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("06034f957724d19d"));
        let original_plaintext = plaintext.clone();
        skinny.cipher(&key, &mut plaintext);
        skinny.decipher(&key, &mut plaintext);
        assert_eq!(plaintext, original_plaintext);
    }

    #[test]
    fn test_inv_mc() {
        let skinny = SKINNYee::default();
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("06034f957724d19d"));
        let original_plaintext = plaintext.clone();
        skinny.mix_columns(&mut plaintext);
        skinny.inv_mix_columns(&mut plaintext);
        assert_eq!(plaintext, original_plaintext);
    }

    #[test]
    fn test_inv_lfsr() {
        let skinny = SKINNYee::default();
        for i in 0..3 {
            let lfsr = &skinny.lfsrs[i];
            let inv_lfsr = &skinny.inv_lfsrs[i];
            for i in 0..16 {
                assert_eq!(i, inv_lfsr.eval(lfsr.eval(i)));
                assert_eq!(i, lfsr.eval(inv_lfsr.eval(i)));
            }
        }
        let skinny_nr = SKINNYee::with_rounds(3);
        for i in 0..3 {
            let lfsr = &skinny_nr.lfsrs[i];
            let inv_lfsr = &skinny_nr.inv_lfsrs[i];
            for i in 0..16 {
                assert_eq!(i, inv_lfsr.eval(lfsr.eval(i)));
                assert_eq!(i, lfsr.eval(inv_lfsr.eval(i)));
            }
        }
    }

    #[test]
    fn test_inv_keyschedule_skinnyee() {
        let skinny = SKINNYee::default();
        let key = Matrix::new(25, 4, parse_nibbles("\
        aaaaaaaa\
        bbbbbbbb\
        cccccccc\
        dddddddd\
        0000000000000000\
        1111111111111111\
        2222222222222222\
        3333333333333333\
        1000
        "));

        fn tki_to_tweakey(tki: &Vec<Matrix<u8>>) -> Matrix<u8> {
            let mut res = Vec::with_capacity(16 * 4);
            for tk in tki {
                for element in &tk.values {
                    res.push(*element);
                }
            }
            Matrix::new(16, 4, res)
        }

        let (_, tweakey, _) = skinny.split_key(&key);
        let tks = skinny.nr_tweak_key_schedule(&tweakey, skinny.nr());
        let last_tweak = tki_to_tweakey(tks.last().unwrap());
        let inv_tks = skinny.inv_nr_tweak_key_schedule(&last_tweak, skinny.nr());
        let first_inv_tweak = tki_to_tweakey(inv_tks.last().unwrap());
        assert_eq!(first_inv_tweak, tweakey);
    }
}