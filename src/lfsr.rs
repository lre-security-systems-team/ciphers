use std::ops::BitXor;

pub struct LFSR<const N: usize> {
    lookup_table: Vec<usize>
}

impl <const N: usize> LFSR<N> {
    pub fn new(bits: [BoolExpr; N]) -> LFSR<N> {
        let mut lookup_table = Vec::with_capacity(1 << bits.len());
        for input in 0..(1 << bits.len()) {
            let output = Self::compute(&bits, input);
            lookup_table.push(output)
        }
        LFSR { lookup_table }
    }

    #[inline]
    pub fn eval(&self, input: usize) -> usize {
        self.lookup_table[input]
    }


    fn compute(bits: &[BoolExpr; N], input: usize) -> usize {
        let mut result = 0;
        for (i, bit) in bits.iter().rev().enumerate() {
            if bit.compute(input) {
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
    fn compute(&self, value: usize) -> bool {
        match self {
            BoolExpr::Bit(pos) => (value >> pos) & 0x1 == 1,
            BoolExpr::BinExpr(expr) => expr.compute(value)
        }
    }
}

pub enum BinaryBooleanExpression {
    XOR(BoolExpr, BoolExpr)
}

impl BinaryBooleanExpression {
    fn compute(&self, value: usize) -> bool {
        match self {
            BinaryBooleanExpression::XOR(lhs, rhs) => lhs.compute(value) ^ rhs.compute(value)
        }
    }
}


