pub mod skinny;
pub mod skinnye_v2;
pub mod skinnyee;

pub trait SymmetricCipher<K, T> {
    fn cipher(&self, key: &K, plaintext: &mut T);
    fn decipher(&self, key: &K, plaintext: &mut T);
}

