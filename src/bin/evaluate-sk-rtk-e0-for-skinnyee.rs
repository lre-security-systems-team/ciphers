use std::fs::File;
use std::io;
use std::io::BufReader;

use clap::Parser;
use rand::{SeedableRng};
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

use crate::ciphers::skinnyee::SKINNYee;
use crate::differential_characteristics::sk_boom_rtk_skinnyee::SingleKeyRelatedTweakeySkinnyEEBoomerangCharacteristic;
use crate::matrix::Matrix;
use crate::skinnyee_boomerang_cli_args::Args;
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

#[path = "../skinnyee_boomerang_cli_args.rs"]
mod skinnyee_boomerang_cli_args;

#[path = "../skinnyee_plaintext_generator.rs"]
mod skinnyee_plaintext_generator;

#[path = "../skinnyee_common.rs"]
mod skinnyee_common;

fn main() -> io::Result<()> {
    let args: Args = Args::parse();
    rayon::ThreadPoolBuilder::new().num_threads(args.nb_threads).build_global().unwrap();
    let seed = [
        6, 3, 14, 7, 11, 12, 0, 15, 8, 2, 1, 10, 4, 5, 9, 13,
        14, 9, 6, 3, 7, 2, 8, 11, 10, 5, 0, 15, 1, 4, 13, 12
    ];

    let mut rand = ChaCha8Rng::from_seed(seed);

    let path = File::open(&args.path).unwrap();
    let reader = BufReader::new(path);
    let dc: SingleKeyRelatedTweakeySkinnyEEBoomerangCharacteristic = serde_json::de::from_reader(reader)?;

    let (cipher, mask) = (SKINNYee::with_rounds(dc.r0 - dc.rm), 0xF);

    let e0_input_difference = dc.e0_em.x[0].iter().flatten().cloned().collect::<Vec<_>>();
    let e0_input_difference = Matrix::new(4, 4, e0_input_difference);

    let e0_output_difference = dc.e0_em.x[dc.r0 - dc.rm].iter().flatten().cloned().collect::<Vec<_>>();
    let e0_output_difference = Matrix::new(4, 4, e0_output_difference);

    let e0_tk0_difference = dc.e0_em.tk[0][0].clone();
    let e0_tk0_difference = Matrix::new(4, 4, e0_tk0_difference);

    let e0_tk1_difference = dc.e0_em.tk[1][0].clone();
    let e0_tk1_difference = Matrix::new(4, 4, e0_tk1_difference);

    let e0_tk2_difference = dc.e0_em.tk[2][0].clone();
    let e0_tk2_difference = Matrix::new(4, 4, e0_tk2_difference);

    let e0_tk3_difference = dc.e0_em.tk[3][0].clone();
    let e0_tk3_difference = Matrix::new(4, 4, e0_tk3_difference);

    let mut number_of_valid_pairs: usize = 0;
    let nb_tries_per_key = args.nb_tries_per_key.unwrap_or(1 << (dc.e0_em.objective + 2));

    let mut key_and_tweakey = vec![0; 100];
    for key_no in 0..args.nb_key {
        fill_random_key_and_tweakey(&mut rand, &mut key_and_tweakey, mask);
        let key_and_tweakey = Matrix::new(25, 4, key_and_tweakey.clone());
        let tk_xor_tke0 = compute_tk_xor_tweakey_difference(
            &key_and_tweakey,
            &e0_tk0_difference,
            &e0_tk1_difference,
            &e0_tk2_difference,
            &e0_tk3_difference
        );

        let generator = SkinnyeePlaintextGenerator::new(&mut rand);
        let number_of_valid_pairs_for_key: usize = generator.take(nb_tries_per_key)
            .par_bridge()
            .map(|p0| evaluate_differential_characteristic(
                &cipher, &key_and_tweakey,
                p0,
                &e0_input_difference,
                &e0_output_difference,
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