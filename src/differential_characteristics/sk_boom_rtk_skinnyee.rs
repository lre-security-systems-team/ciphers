use serde::{Deserialize, Serialize};
use crate::differential_characteristics::sk_rtk_skinnyee::SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic;

#[derive(Serialize, Deserialize)]
pub struct SingleKeyRelatedTweakeySkinnyEEBoomerangCharacteristic {
    #[serde(rename="E0EM")]
    pub e0_em: SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic,
    #[serde(rename="EME1")]
    pub em_e1: SingleKeyRelatedTweakeySkinnyEEDifferentialCharacteristic,
    pub r0: usize,
    pub rm: usize,
    pub r1: usize,
}