use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use crate::matrix::Matrix;

pub struct SkinnyeePlaintextGenerator<'r> {
    rand: &'r mut ChaCha8Rng
}

impl <'r> SkinnyeePlaintextGenerator<'r> {
    pub fn new(rand: &'r mut ChaCha8Rng) -> SkinnyeePlaintextGenerator<'r> {
        SkinnyeePlaintextGenerator { rand }
    }
}

impl <'r> Iterator for SkinnyeePlaintextGenerator<'r> {
    type Item = Matrix<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut plaintext = Vec::with_capacity(16);
        let key = self.rand.next_u64();
        for i in 0..16 {
            plaintext.push((key >> (i * 4) & 0xF) as u8);
        }
        Some(Matrix::new(4, 4, plaintext))
    }
}