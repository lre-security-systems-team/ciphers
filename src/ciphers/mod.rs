pub mod skinny;
pub mod skinnye_v2;

pub trait SymmetricCipher<K, T> {
    fn cipher(&self, key: &K, plaintext: &mut T);
}

