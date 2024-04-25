use std::path::PathBuf;
use clap::Parser;

#[derive(Parser)]
pub struct Args {
    #[arg(short('k'), long, default_value_t = 8)]
    pub nb_key: usize,
    #[arg(short, long)]
    pub nb_tries_per_key: Option<usize>,
    #[arg(short, long)]
    pub path: PathBuf,
    #[arg(short('t'), long, default_value_t=1)]
    pub nb_threads: usize
}