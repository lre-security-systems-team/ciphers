use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use rand::{RngCore, SeedableRng};
use rand_xoshiro::Xoshiro256StarStar;
use ciphers::skinny::SKINNY;
use crate::ciphers::SymmetricCipher;
use crate::matrix::Matrix;
use crate::differential_characteristics::sk_skinny::SingleKeySkinnyDifferentialCharacteristic;
use clap::{Parser};

#[path = "../matrix.rs"]
mod matrix;
#[path = "../ciphers/mod.rs"]
mod ciphers;
#[path = "../lfsr.rs"]
mod lfsr;
#[path = "../differential_characteristics/mod.rs"]
mod differential_characteristics;

#[derive(Copy, Clone, clap::ValueEnum)]
enum Version {
    v64,
    v128,
}

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    version: Version,
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
    let dc: SingleKeySkinnyDifferentialCharacteristic = serde_json::de::from_reader(reader)?;

    let (cipher, mask) = match args.version {
        Version::v64 => (SKINNY::v64_with_rounds(dc.x.len() - 1), 0xF),
        Version::v128 => (SKINNY::v128_with_rounds(dc.x.len() - 1), 0xFF),
    };

    let input_difference = dc.x.first().unwrap().iter().flatten().cloned().collect::<Vec<_>>();
    let mut input_difference = Matrix::new(4, 4, input_difference);

    let output_difference = dc.x.last().unwrap().iter().flatten().cloned().collect::<Vec<_>>();
    let mut output_difference = Matrix::new(4, 4, output_difference);

    let mut number_of_valid_pairs: i32 = 0;
    let nb_tries_per_key = args.nb_tries_per_key.unwrap_or(1 << (dc.objective + 2));

    for _ in 0..args.nb_key {
        let mut key = Vec::with_capacity(16);
        for _ in 0..16 {
            key.push(rand.next_u64() as u8 & mask);
        }
        let key = Matrix::new(1, 16, key);
        for _ in 0..nb_tries_per_key {
            let mut p_values = Vec::with_capacity(16);
            for _ in 0..16 {
                p_values.push(rand.next_u64() as u8 & mask)
            }
            let mut p0 = Matrix::new(4, 4, p_values);
            let mut p1 = &p0 ^ &input_difference;
            cipher.cipher(&key, &mut p0);
            cipher.cipher(&key, &mut p1);
            let d_out = &p0 ^ &p1;
            if output_difference == d_out {
                number_of_valid_pairs += 1;
            }
        }
    }

    println!("{}/{} : {}", number_of_valid_pairs, nb_tries_per_key * args.nb_key, (number_of_valid_pairs as f64).log2() - ((nb_tries_per_key * args.nb_key) as f64).log2());
    Ok(())
}
