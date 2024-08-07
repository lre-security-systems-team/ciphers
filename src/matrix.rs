use std::fmt::{Debug, Formatter, Write};
use std::ops::{BitXor, BitXorAssign, Index, IndexMut};
use std::slice::{Iter, IterMut};


pub struct Matrix<T> {
    m: usize,
    n: usize,
    pub values: Vec<T>,
}

impl<T: Debug> Debug for Matrix<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for row in 0..self.m {
            let mut row_serializer  = f.debug_list();
            for col in 0..self.n {
                row_serializer.entry(&self[(row, col)]);
            }
            row_serializer.finish()?;
            f.write_char('\n')?;
        }
        Ok(())
    }
}

impl<T: Eq> Eq for Matrix<T> {}

impl<T: PartialEq> PartialEq for Matrix<T> {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.m == other.m && self.values == other.values
    }
}

impl<T> Clone for Matrix<T> where T: Clone {
    fn clone(&self) -> Self {
        Matrix {
            m: self.m,
            n: self.n,
            values: self.values.clone(),
        }
    }
}

impl<T> Matrix<T> {
    pub fn empty() -> Matrix<T> {
        Matrix {
            m: 0,
            n: 0,
            values: Vec::with_capacity(0),
        }
    }
    pub fn new(m: usize, n: usize, values: Vec<T>) -> Matrix<T> {
        assert_eq!(m * n, values.len());
        Matrix { m, n, values }
    }

    fn index(&self, index: (usize, usize)) -> usize {
        assert!(index.0 < self.m && index.1 < self.n);
        index.0 * self.n + index.1
    }

    pub fn iter(&self) -> Iter<'_, T> {
        self.values.iter()
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        self.values.iter_mut()
    }
}

impl<T> Index<(usize, usize)> for Matrix<T> {
    type Output = T;

    fn index(&self, index: (usize, usize)) -> &Self::Output {
        &self.values[self.index(index)]
    }
}

impl<T> IndexMut<(usize, usize)> for Matrix<T> {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut Self::Output {
        let i = self.index(index);
        &mut self.values[i]
    }
}

impl BitXor for &Matrix<u8> {
    type Output = Matrix<u8>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        assert!(self.m == rhs.m && self.n == rhs.n);
        Matrix::new(self.m, self.n, self.values.iter().zip(rhs.values.iter()).map(|(l, r)| *l ^ *r).collect())
    }
}


impl BitXor for Matrix<u8> {
    type Output = Matrix<u8>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        assert!(self.m == rhs.m && self.n == rhs.n);
        Matrix::new(self.m, self.n, self.values.iter().zip(rhs.values).map(|(l, r)| *l ^ r).collect())
    }
}

impl BitXorAssign for Matrix<u8> {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self ^= &rhs;
    }
}

impl BitXorAssign<&Matrix<u8>> for Matrix<u8> {
    fn bitxor_assign(&mut self, rhs: &Matrix<u8>) {
        assert!(self.m == rhs.m && self.n == rhs.n);
        self.values.iter_mut().zip(rhs.values.iter()).for_each(|(l, r)| *l ^= *r);
    }
}