use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::PathBuf;

use clap::Parser;
use rand::{SeedableRng};
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

use crate::ciphers::skinnyee::SKINNYee;
use crate::differential_characteristics::sk_rtk_skinnyee::SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic;
use crate::matrix::Matrix;
use crate::skinnyee_common::{compute_tk_xor_tweakey_difference, evaluate_differential_characteristic, fill_random_key_and_tweakey};
use crate::skinnyee_plaintext_generator::SkinnyeePlaintextGenerator;

#[path = "../matrix.rs"]
mod matrix;
#[path = "../ciphers/mod.rs"]
mod ciphers;
#[path = "../lfsr.rs"]
mod lfsr;
#[path = "../differential_characteristics/mod.rs"]
mod differential_characteristics;

#[path = "../skinnyee_plaintext_generator.rs"]
mod skinnyee_plaintext_generator;

#[path = "../skinnyee_common.rs"]
mod skinnyee_common;


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
    let dc: SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic = serde_json::de::from_reader(reader)?;

    let (cipher, mask) = (SKINNYee::with_rounds(dc.x.len() - 1), 0xF);

    let input_difference = dc.x.first().unwrap().iter().flatten().cloned().collect::<Vec<_>>();
    let input_difference = Matrix::new(4, 4, input_difference);

    let output_difference = dc.x.last().unwrap().iter().flatten().cloned().collect::<Vec<_>>();
    let output_difference = Matrix::new(4, 4, output_difference);

    let tk0_difference = dc.tk[0].first().unwrap().clone();
    let tk0_difference = Matrix::new(4, 4, tk0_difference);

    let tk1_difference = dc.tk[1].first().unwrap().clone();
    let tk1_difference = Matrix::new(4, 4, tk1_difference);

    let tk2_difference = dc.tk[2].first().unwrap().clone();
    let tk2_difference = Matrix::new(4, 4, tk2_difference);

    let tk3_difference = dc.tk[3].first().unwrap().clone();
    let tk3_difference = Matrix::new(4, 4, tk3_difference);

    let mut number_of_valid_pairs: usize = 0;
    let nb_tries_per_key = args.nb_tries_per_key.unwrap_or(1 << (dc.objective + 2));

    let mut key_and_tweakey = vec![0; 100];
    for key_no in 0..args.nb_key {
        fill_random_key_and_tweakey(&mut rand, &mut key_and_tweakey, mask);
        let key_and_tweakey = Matrix::new(25, 4, key_and_tweakey.clone());
        let tk_xor_tke0 = compute_tk_xor_tweakey_difference(
            &key_and_tweakey,
            &tk0_difference,
            &tk1_difference,
            &tk2_difference,
            &tk3_difference
        );

        let generator = SkinnyeePlaintextGenerator::new(&mut rand);
        let number_of_valid_pairs_for_key: usize = generator.take(nb_tries_per_key)
            .par_bridge()
            .map(|p0| evaluate_differential_characteristic(
                &cipher, &key_and_tweakey,
                p0,
                &input_difference,
                &output_difference,
                &tk_xor_tke0
            ))
            .fold(|| 0usize, |a, b| a + b)
            .sum();

        number_of_valid_pairs += number_of_valid_pairs_for_key;
        println!("Random Key {} - {}/{} : 2^{{{}}}", key_no, number_of_valid_pairs_for_key, nb_tries_per_key, (number_of_valid_pairs_for_key as f64).log2() - ((nb_tries_per_key) as f64).log2());
    }

    println!("Total - {}/{} : 2^{{{}}}", number_of_valid_pairs, nb_tries_per_key * args.nb_key, (number_of_valid_pairs as f64).log2() - ((nb_tries_per_key * args.nb_key) as f64).log2());
    println!("Mean  - {}/{} : 2^{{{}}}", number_of_valid_pairs as f64 / args.nb_key as f64, nb_tries_per_key, (number_of_valid_pairs as f64 / args.nb_key as f64).log2() - ((nb_tries_per_key) as f64).log2());
    Ok(())
}
