use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic {
    #[serde(rename="X")]
    pub x: Vec<Vec<Vec<u8>>>,
    #[serde(rename="SC")]
    pub sc: Vec<Vec<Vec<u8>>>,
    #[serde(rename="TK")]
    pub tk: Vec<Vec<Vec<u8>>>,
    pub objective: usize
}