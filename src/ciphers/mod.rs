pub mod skinny;

pub trait SymmetricCipher<K, T> {
    fn cipher(&self, key: &K, plaintext: &mut T);
}

pub enum Shift {
    Left,
    Right,
}

pub fn lfsr(nb_bits: usize, poly: usize, direction: Shift, value: usize) -> usize {
    let word_mask = (1 << nb_bits) - 1;
    let mut inserted_bits = 0;
    for i in 0..nb_bits {
        if (value & poly) & (1 << i) != 0 {
            inserted_bits ^= 1;
        }
    }

    match direction {
        Shift::Left => ((value << 1) | inserted_bits) & word_mask,
        Shift::Right => (inserted_bits << nb_bits - 1) | (value >> 1)
    }
}
