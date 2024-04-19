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
use crate::ciphers::skinnyee::SKINNYee;
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

    let mut rand = Xoshiro256StarStar::from_seed(seed);

    let path = File::open(&args.path).unwrap();
    let reader = BufReader::new(path);
    let dc: SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic = serde_json::de::from_reader(reader)?;

    let (cipher, mask) = (SKINNYee::with_rounds(dc.x.len() - 1), 0xF);

    let input_difference = dc.x.first().unwrap().iter().flatten().cloned().collect::<Vec<_>>();
    let mut input_difference = Matrix::new(4, 4, input_difference);

    let output_difference = dc.x.last().unwrap().iter().flatten().cloned().collect::<Vec<_>>();
    let mut output_difference = Matrix::new(4, 4, output_difference);

    let tk0_difference = dc.tk[0].first().unwrap().clone();
    let mut tk0_difference = Matrix::new(4, 4, tk0_difference);

    let tk1_difference = dc.tk[1].first().unwrap().clone();
    let mut tk1_difference = Matrix::new(4, 4, tk1_difference);

    let tk2_difference = dc.tk[2].first().unwrap().clone();
    let mut tk2_difference = Matrix::new(4, 4, tk2_difference);

    let tk3_difference = dc.tk[3].first().unwrap().clone();
    let mut tk3_difference = Matrix::new(4, 4, tk3_difference);

    let mut number_of_valid_pairs: i32 = 0;
    let nb_tries_per_key = args.nb_tries_per_key.unwrap_or(1 << (dc.objective + 2));

    for _ in 0..args.nb_key {
        let mut key = Vec::with_capacity(100);
        for _ in 0..100 {
            key.push(rand.next_u64() as u8 & mask);
        }
        key[24 * 4] &= 0b111;
        key[24 * 4 + 1] = 0;
        key[24 * 4 + 2] = 0;
        key[24 * 4 + 3] = 0;
        let key = Matrix::new(25, 4, key);
        let mut related_tweakey = key.clone();
        for i in 0..4 {
            for j in 0.. 4 {
                related_tweakey[(8 + i, j)]  ^= tk0_difference[(i, j)];
                related_tweakey[(12 + i, j)] ^= tk1_difference[(i, j)];
                related_tweakey[(16 + i, j)] ^= tk2_difference[(i, j)];
                related_tweakey[(20 + i, j)] ^= tk3_difference[(i, j)];
            }
        }
        for _ in 0..nb_tries_per_key {
            let mut p_values = Vec::with_capacity(16);
            for _ in 0..16 {
                p_values.push(rand.next_u64() as u8 & mask)
            }
            let mut p0 = Matrix::new(4, 4, p_values);
            let mut p1 = &p0 ^ &input_difference;
            cipher.cipher(&key, &mut p0);
            cipher.cipher(&related_tweakey, &mut p1);
            let d_out = &p0 ^ &p1;
            if output_difference == d_out {
                number_of_valid_pairs += 1;
            }
        }
    }

    println!("{}/{} : {}", number_of_valid_pairs, nb_tries_per_key * args.nb_key, (number_of_valid_pairs as f64).log2() - ((nb_tries_per_key * args.nb_key) as f64).log2());
    Ok(())
}
