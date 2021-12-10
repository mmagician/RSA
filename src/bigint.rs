use alloc::boxed::Box;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use std::cmp::{PartialEq, PartialOrd};

pub enum BigUInteger {
    Default(Box<BigUint>),
}

impl FromPrimitive for BigUInteger {
    fn from_i64(n: i64) -> Option<Self> {
        todo!()
    }

    fn from_u64(n: u64) -> Option<Self> {
        Some(BigUInteger::Default(Box::new(
            BigUint::from_u64(n).unwrap(),
        )))
    }
}

impl PartialEq<BigUint> for BigUInteger {
    fn eq(&self, other: &BigUint) -> bool {
        match self {
            BigUInteger::Default(bigu) => bigu.as_ref().eq(other),
        }
    }
}

impl PartialOrd<BigUint> for BigUInteger {
    fn partial_cmp(&self, other: &BigUint) -> Option<std::cmp::Ordering> {
        match self {
            BigUInteger::Default(bigu) => Some(bigu.as_ref().cmp(other)),
        }
    }
}

impl PartialEq<BigUInteger> for BigUint {
    fn eq(&self, other: &BigUInteger) -> bool {
        match other {
            BigUInteger::Default(bigu) => other.eq(bigu.as_ref()),
        }
    }
}

impl PartialOrd<BigUInteger> for BigUint {
    fn partial_cmp(&self, other: &BigUInteger) -> Option<std::cmp::Ordering> {
        match other {
            BigUInteger::Default(bigu) => Some(self.cmp(bigu.as_ref())),
        }
    }
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::BigUint;
    use crate::bigint::BigUInteger;

    #[test]
    fn test_bigint_partial_ord() {
        let a = BigUint::from_u64(5).unwrap();
        let b = BigUInteger::from_u64(6).unwrap();

        assert!(b > a);
    }
}
