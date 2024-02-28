use serde::{Deserialize, Serialize};
use crate::matrix::Matrix;

#[derive(Serialize, Deserialize)]
pub struct SingleKeySkinnyDifferentialCharacteristic {
    #[serde(rename="X")]
    pub x: Vec<Vec<Vec<u8>>>,
    #[serde(rename="SC")]
    pub sc: Vec<Vec<Vec<u8>>>,
    pub objective: usize
}