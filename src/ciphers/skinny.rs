use std::mem::swap;
use std::vec;
use crate::ciphers::SymmetricCipher;
use crate::lfsr::{LFSR, x};
use crate::matrix::Matrix;

const SKINNY_64_SBOX: [u8; 16] = [
    12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15
];

const SKINNY_128_SBOX: [u8; 256] = [
    0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
    0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
    0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
    0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
    0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
    0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
    0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
    0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
    0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
    0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
    0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
    0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
    0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
    0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
    0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
    0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff
];

const RC: [u8; 62] = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33,
    0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B,
    0x17, 0x2E, 0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A, 0x34, 0x29,
    0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13, 0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a,
    0x15, 0x2a, 0x14, 0x28, 0x10, 0x20
];


const NR: [[usize; 3]; 2] = [
    [32, 36, 40],
    [40, 48, 56]
];

const PT: [usize; 16] = [
    9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7
];

#[allow(dead_code)]
pub enum SKINNY {
    Skinny64 { r: Option<usize>, lfsrs: Vec<LFSR<4>> },
    Skinny128 { r: Option<usize>, lfsrs: Vec<LFSR<8>> },
}

impl SKINNY {
    #[allow(dead_code)]
    pub fn v64() -> SKINNY {
        SKINNY::Skinny64 {
            r: None,
            lfsrs: vec![
                LFSR::new([x(2), x(1), x(0), x(3) ^ x(2)]),
                LFSR::new([x(0) ^ x(3), x(3), x(2), x(1)]),
            ],
        }
    }

    #[allow(dead_code)]
    pub fn v64_with_rounds(rounds: usize) -> SKINNY {
        SKINNY::Skinny64 {
            r: Some(rounds),
            lfsrs: vec![
                LFSR::new([x(2), x(1), x(0), x(3) ^ x(2)]),
                LFSR::new([x(0) ^ x(3), x(3), x(2), x(1)]),
            ],
        }
    }

    #[allow(dead_code)]
    pub fn v128() -> SKINNY {
        SKINNY::Skinny128 {
            r: None,
            lfsrs: vec![
                LFSR::new([x(6), x(5), x(4), x(3), x(2), x(1), x(0), x(7) ^ x(5)]),
                LFSR::new([x(0) ^ x(6), x(7), x(6), x(5), x(4), x(3), x(2), x(1)]),
            ],
        }
    }
    #[allow(dead_code)]
    pub fn v128_with_rounds(rounds: usize) -> SKINNY {
        SKINNY::Skinny128 {
            r: Some(rounds),
            lfsrs: vec![
                LFSR::new([x(6), x(5), x(4), x(3), x(2), x(1), x(0), x(7) ^ x(5)]),
                LFSR::new([x(0) ^ x(6), x(7), x(6), x(5), x(4), x(3), x(2), x(1)]),
            ],
        }
    }
    #[inline]
    fn nr(&self, tk: usize) -> usize {
        match self {
            SKINNY::Skinny64 { r, .. } => r.unwrap_or(NR[0][tk - 1]),
            SKINNY::Skinny128 { r, .. } => r.unwrap_or(NR[1][tk - 1]),
        }
    }

    #[inline]
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

    #[inline]
    fn lfsr(&self, i: usize, value: u8) -> u8 {
        match &self {
            &SKINNY::Skinny64 { lfsrs, .. } => lfsrs[i - 2].eval(value as usize) as u8,
            &SKINNY::Skinny128 { lfsrs, .. } => lfsrs[i - 2].eval(value as usize) as u8,
        }
    }

    #[inline]
    fn add_round_tweak_key(&self, internal_state: &mut Matrix<u8>, round_tweak_key: &Vec<Matrix<u8>>, tk: usize) {
        for i in 0..=1 {
            for j in 0..4 {
                internal_state[(i, j)] ^= (1..=tk).fold(0, |acc, z| acc ^ round_tweak_key[z][(i, j)]);
            }
        }
    }

    #[inline]
    fn add_constants(&self, internal_state: &mut Matrix<u8>, r: usize) {
        let rc = RC[r];
        let c0 = rc & 0xF;
        let c1 = rc >> 4;
        let c2 = 0x02;
        internal_state[(0, 0)] ^= c0;
        internal_state[(1, 0)] ^= c1;
        internal_state[(2, 0)] ^= c2;
    }
    #[inline]
    fn sub_cells(&self, internal_state: &mut Matrix<u8>) {
        match self {
            SKINNY::Skinny64 { .. } => Self::sub_cells_64(internal_state),
            SKINNY::Skinny128 { .. } => Self::sub_cells_128(internal_state),
        }
    }
    #[inline]
    fn sub_cells_64(internal_state: &mut Matrix<u8>) {
        internal_state.iter_mut()
            .for_each(|it| *it = SKINNY_64_SBOX[*it as usize])
    }
    #[inline]
    fn sub_cells_128(internal_state: &mut Matrix<u8>) {
        internal_state.iter_mut()
            .for_each(|it| *it = SKINNY_128_SBOX[*it as usize])
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
    fn mix_columns(&self, internal_state: &mut Matrix<u8>) {
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
}

impl SymmetricCipher<Matrix<u8>, Matrix<u8>> for SKINNY {
    fn cipher(&self, key: &Matrix<u8>, plaintext: &mut Matrix<u8>) {
        let tk = key.values.len() / plaintext.values.len();
        assert!(tk == 1 || tk == 2 || tk == 3);
        let round_tweak_keys = self.key_schedule(key, tk);
        for round_num in 0..self.nr(tk) {
            self.sub_cells(plaintext);
            self.add_constants(plaintext, round_num);
            self.add_round_tweak_key(plaintext, &round_tweak_keys[round_num], tk);
            self.shift_rows(plaintext);
            self.mix_columns(plaintext);
        }
    }

    fn decipher(&self, _key: &Matrix<u8>, _plaintext: &mut Matrix<u8>) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::ciphers::skinny::SKINNY;
    use crate::ciphers::SymmetricCipher;
    use crate::matrix::Matrix;

    fn parse_nibbles(word: &'static str) -> Vec<u8> {
        fn parse_digit(c: char) -> u8 {
            c.to_digit(16).unwrap() as u8
        }

        word.chars().map(parse_digit).collect()
    }

    fn parse_bytes(word: &'static str) -> Vec<u8> {
        fn parse_digit(s: String) -> u8 {
            u8::from_str_radix(&s, 16).unwrap()
        }

        word.chars().collect::<Vec<_>>()
            .chunks(2)
            .map(|it| it.iter().collect::<String>())
            .map(parse_digit)
            .collect()
    }

    #[test]
    fn test_vector_skinny_64_64() {
        let skinny = SKINNY::v64();
        let key = Matrix::new(1, 16, parse_nibbles("f5269826fc681238"));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("06034f957724d19d"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("bb39dfb2429b8ac7"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinny_64_128() {
        let skinny = SKINNY::v64();
        let key = Matrix::new(2, 16, parse_nibbles("9eb93640d088da6376a39d1c8bea71e1"));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("cf16cfe8fd0f98aa"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("6ceda1f43de92b9e"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinny_64_192() {
        let skinny = SKINNY::v64();
        let key = Matrix::new(3, 16, parse_nibbles("ed00c85b120d68618753e24bfd908f60b2dbb41b422dfcd0"));
        let mut plaintext = Matrix::new(4, 4, parse_nibbles("530c61d35e8663c3"));
        let ciphertext = Matrix::new(4, 4, parse_nibbles("dd2cf1a8f330303c"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinny_128_128() {
        let skinny = SKINNY::v128();
        let key = Matrix::new(1, 16, parse_bytes("4f55cfb0520cac52fd92c15f37073e93"));
        let mut plaintext = Matrix::new(4, 4, parse_bytes("f20adb0eb08b648a3b2eeed1f0adda14"));
        let ciphertext = Matrix::new(4, 4, parse_bytes("22ff30d498ea62d7e45b476e33675b74"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinny_128_256() {
        let skinny = SKINNY::v128();
        let key = Matrix::new(2, 16, parse_bytes("009cec81605d4ac1d2ae9e3085d7a1f31ac123ebfc00fddcf01046ceeddfcab3"));
        let mut plaintext = Matrix::new(4, 4, parse_bytes("3a0c47767a26a68dd382a695e7022e25"));
        let ciphertext = Matrix::new(4, 4, parse_bytes("b731d98a4bde147a7ed4a6f16b9b587f"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }

    #[test]
    fn test_vector_skinny_128_384() {
        let skinny = SKINNY::v128();
        let key = Matrix::new(3, 16, parse_bytes("df889548cfc7ea52d296339301797449ab588a34a47f1ab2dfe9c8293fbea9a5ab1afac2611012cd8cef952618c3ebe8"));
        let mut plaintext = Matrix::new(4, 4, parse_bytes("a3994b66ad85a3459f44e92b08f550cb"));
        let ciphertext = Matrix::new(4, 4, parse_bytes("94ecf589e2017c601b38c6346a10dcfa"));
        skinny.cipher(&key, &mut plaintext);
        assert_eq!(plaintext, ciphertext);
    }
}