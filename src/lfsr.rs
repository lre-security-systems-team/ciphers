use std::ops::BitXor;

pub struct LFSR<const N: usize> {
    pub bits: [BoolExpr; N],
}

impl <const N: usize> LFSR<N> {
    pub fn new(bits: [BoolExpr; N]) -> LFSR<N> {
        LFSR { bits }
    }

    pub fn eval(&self, input: usize) -> usize {
        let mut result = 0;
        for (i, bit) in self.bits.iter().rev().enumerate() {
            if bit.eval(input) {
                result |= 1 << i;
            }
        }
        result
    }
}

pub enum BoolExpr {
    Bit(usize),
    BinExpr(Box<BinaryBooleanExpression>),
}

pub fn x(pos: usize) -> BoolExpr {
    BoolExpr::Bit(pos)
}

impl BitXor for BoolExpr {
    type Output = BoolExpr;

    fn bitxor(self, rhs: Self) -> Self::Output {
        BoolExpr::BinExpr(Box::new(
            BinaryBooleanExpression::XOR(self, rhs)
        ))
    }
}

impl BoolExpr {
    fn eval(&self, value: usize) -> bool {
        match self {
            BoolExpr::Bit(pos) => (value >> pos) & 0x1 == 1,
            BoolExpr::BinExpr(expr) => expr.eval(value)
        }
    }
}

pub enum BinaryBooleanExpression {
    XOR(BoolExpr, BoolExpr)
}

impl BinaryBooleanExpression {
    fn eval(&self, value: usize) -> bool {
        match self {
            BinaryBooleanExpression::XOR(lhs, rhs) => lhs.eval(value) ^ rhs.eval(value)
        }
    }
}


