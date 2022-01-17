pub type Result<T> = core::result::Result<T, Error>;

/// Error types
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Verification,
    MessageTooLong,
    InputNotHashed,
    InvalidPrime,
    InvalidModulus,
    InvalidCoefficient,
    Internal,
    TooSmallBitSize,
    QuadraticResidueNotFound,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Verification => write!(f, "verification error"),
            Error::MessageTooLong => write!(f, "message too long"),
            Error::InputNotHashed => write!(f, "input must be hashed"),
            Error::InvalidPrime => write!(f, "invalid prime value"),
            Error::InvalidModulus => write!(f, "invalid modulus"),
            Error::InvalidCoefficient => write!(f, "invalid coefficient"),
            Error::Internal => write!(f, "internal error"),
            Error::TooSmallBitSize => write!(f, "too few bits requested"),
            Error::QuadraticResidueNotFound => write!(f, "no quadratic residue for this value"),
        }
    }
}
