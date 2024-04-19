use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use rand::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256StarStar;
use crate::ciphers::SymmetricCipher;
use crate::matrix::Matrix;
use crate::differential_characteristics::sk_skinny::SingleKeySkinnyDifferentialCharacteristic;
use clap::{Parser};
use rand_chacha::{ChaCha20Rng, ChaCha8Rng};
use crate::ciphers::skinnyee::SKINNYee;
use crate::differential_characteristics::sk_boom_rtk_skinnyee::SingleKeyRelatedTweakeySkinnyEEBoomerangCharacteristic;
use crate::differential_characteristics::sk_rtk_skinnyee::SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic;

#[path = "../matrix.rs"]
mod matrix;
#[path = "../ciphers/mod.rs"]
mod ciphers;
#[path = "../lfsr.rs"]
mod lfsr;
#[path = "../differential_characteristics/mod.rs"]
mod differential_characteristics;

#[derive(Parser)]
struct Args {
    #[arg(short('k'), long, default_value_t = 8)]
    nb_key: usize,
    #[arg(short, long)]
    nb_tries_per_key: Option<usize>,
    #[arg(short, long)]
    path: PathBuf,
}

fn main() -> io::Result<()> {
    let args: Args = Args::parse();
    let seed = [
        6, 3, 14, 7, 11, 12, 0, 15, 8, 2, 1, 10, 4, 5, 9, 13,
        14, 9, 6, 3, 7, 2, 8, 11, 10, 5, 0, 15, 1, 4, 13, 12
    ];

    let mut rand = ChaCha8Rng::from_seed(seed);

    let path = File::open(&args.path).unwrap();
    let reader = BufReader::new(path);
    let dc: SingleKeyRelatedTweakeySkinnyEEBoomerangCharacteristic = serde_json::de::from_reader(reader)?;

    let (cipher, mask) = (SKINNYee::with_rounds(dc.rm), 0xF);

    let e0_input_difference = dc.e0_em.x[dc.r0 - dc.rm].iter().flatten().cloned().collect::<Vec<_>>();
    let e0_input_difference = Matrix::new(4, 4, e0_input_difference);

    let e1_output_difference = dc.em_e1.x[dc.rm + 1].iter().flatten().cloned().collect::<Vec<_>>();
    let e1_output_difference = Matrix::new(4, 4, e1_output_difference);

    let e0_tk0_difference = dc.e0_em.tk[0][dc.r0 - dc.rm].clone();
    let e0_tk0_difference = Matrix::new(4, 4, e0_tk0_difference);

    let e0_tk1_difference = dc.e0_em.tk[1][dc.r0 - dc.rm].clone();
    let e0_tk1_difference = Matrix::new(4, 4, e0_tk1_difference);

    let e0_tk2_difference = dc.e0_em.tk[2][dc.r0 - dc.rm].clone();
    let e0_tk2_difference = Matrix::new(4, 4, e0_tk2_difference);

    let e0_tk3_difference = dc.e0_em.tk[3][dc.r0 - dc.rm].clone();
    let e0_tk3_difference = Matrix::new(4, 4, e0_tk3_difference);

    let e1_tk0_difference = dc.em_e1.tk[0][dc.r0 - dc.rm].clone();
    let e1_tk0_difference = Matrix::new(4, 4, e1_tk0_difference);

    let e1_tk1_difference = dc.em_e1.tk[1][dc.r0 - dc.rm].clone();
    let e1_tk1_difference = Matrix::new(4, 4, e1_tk1_difference);

    let e1_tk2_difference = dc.em_e1.tk[2][dc.r0 - dc.rm].clone();
    let e1_tk2_difference = Matrix::new(4, 4, e1_tk2_difference);

    let e1_tk3_difference = dc.em_e1.tk[3][dc.r0 - dc.rm].clone();
    let e1_tk3_difference = Matrix::new(4, 4, e1_tk3_difference);

    let mut number_of_valid_pairs: i32 = 0;
    let nb_tries_per_key = args.nb_tries_per_key.unwrap_or(1 << (dc.e0_em.objective + dc.em_e1.objective + 2));

    let mut key_and_tweakey = vec![0; 100];
    for key_no in 0..args.nb_key {
        let mut number_of_valid_pairs_for_key: i32 = 0;
        rand.fill_bytes(&mut key_and_tweakey);
        key_and_tweakey.iter_mut().for_each(|it| *it &= mask);
        // Mask the RCi 3-bit word initializer
        key_and_tweakey[24 * 4] &= 0b111;
        // Remove mask the three last unused words
        key_and_tweakey[24 * 4 + 1] = 0;
        key_and_tweakey[24 * 4 + 2] = 0;
        key_and_tweakey[24 * 4 + 3] = 0;
        let key_and_tweakey = Matrix::new(25, 4, key_and_tweakey.clone());
        let mut tk_xor_tke0 = key_and_tweakey.clone();
        let mut tk_xor_tke1 = key_and_tweakey.clone();
        let mut tk_xor_tke0_xor_tke1 = key_and_tweakey.clone();

        for i in 0..4 {
            for j in 0..4 {
                tk_xor_tke0[(8 + i, j)] ^= &e0_tk0_difference[(i, j)];
                tk_xor_tke0[(12 + i, j)] ^= &e0_tk1_difference[(i, j)];
                tk_xor_tke0[(16 + i, j)] ^= &e0_tk2_difference[(i, j)];
                tk_xor_tke0[(20 + i, j)] ^= &e0_tk3_difference[(i, j)];

                tk_xor_tke1[(8 + i, j)] ^= &e1_tk0_difference[(i, j)];
                tk_xor_tke1[(12 + i, j)] ^= &e1_tk1_difference[(i, j)];
                tk_xor_tke1[(16 + i, j)] ^= &e1_tk2_difference[(i, j)];
                tk_xor_tke1[(20 + i, j)] ^= &e1_tk3_difference[(i, j)];

                tk_xor_tke0_xor_tke1[(8 + i, j)] ^= &e0_tk0_difference[(i, j)];
                tk_xor_tke0_xor_tke1[(12 + i, j)] ^= &e0_tk1_difference[(i, j)];
                tk_xor_tke0_xor_tke1[(16 + i, j)] ^= &e0_tk2_difference[(i, j)];
                tk_xor_tke0_xor_tke1[(20 + i, j)] ^= &e0_tk3_difference[(i, j)];

                tk_xor_tke0_xor_tke1[(8 + i, j)] ^= &e1_tk0_difference[(i, j)];
                tk_xor_tke0_xor_tke1[(12 + i, j)] ^= &e1_tk1_difference[(i, j)];
                tk_xor_tke0_xor_tke1[(16 + i, j)] ^= &e1_tk2_difference[(i, j)];
                tk_xor_tke0_xor_tke1[(20 + i, j)] ^= &e1_tk3_difference[(i, j)];
            }
        }
        for _ in 0..nb_tries_per_key {
            let mut p_values = Vec::with_capacity(16);
            for _ in 0..16 {
                p_values.push(rand.next_u64() as u8 & mask)
            }

            let mut p0 = Matrix::new(4, 4, p_values);
            let mut p1 = &p0 ^ &e0_input_difference;
            cipher.cipher(&key_and_tweakey, &mut p0);
            p0 ^= &e1_output_difference;
            cipher.decipher(&tk_xor_tke1, &mut p0);

            cipher.cipher(&tk_xor_tke0, &mut p1);
            p1 ^= &e1_output_difference;
            cipher.decipher(&tk_xor_tke0_xor_tke1, &mut p1);

            let d_out = &p0 ^ &p1;
            if e0_input_difference == d_out {
                number_of_valid_pairs_for_key += 1;
            }
        }
        number_of_valid_pairs += number_of_valid_pairs_for_key;
        println!("Random Key {} - {}/{} : 2^{{{}}}", key_no, number_of_valid_pairs_for_key, nb_tries_per_key, (number_of_valid_pairs_for_key as f64).log2() - ((nb_tries_per_key) as f64).log2());
    }

    println!("Total - {}/{} : 2^{{{}}}", number_of_valid_pairs, nb_tries_per_key * args.nb_key, (number_of_valid_pairs as f64).log2() - ((nb_tries_per_key * args.nb_key) as f64).log2());
    println!("Mean  - {}/{} : 2^{{{}}}", number_of_valid_pairs as f64 / args.nb_key as f64, nb_tries_per_key, (number_of_valid_pairs as f64 / args.nb_key as f64).log2() - ((nb_tries_per_key) as f64).log2());
    Ok(())
}

struct Rand {
    v: usize,
}

impl Rand {
    fn new(seed: usize) -> Rand {
        let mut v = 4101842887655102017usize;
        v ^= seed;
        v = Self::next(v);
        Rand { v }
    }

    fn next_usize(&mut self) -> usize {
        self.v = Self::next(self.v);
        self.v
    }

    fn next_u64(&mut self) -> u64 {
        self.next_usize() as u64
    }

    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next(mut v: usize) -> usize {
        v ^= (v >> 21);
        v ^= (v << 35);
        v ^= (v >> 4);
        let (v, _) = v.overflowing_mul(2685821657736338717);
        v
    }
}