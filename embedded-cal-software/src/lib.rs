//! libcrux-sha2 backed SHA-256, plus plumbing to extend any hardware-backed [`Cal`] with it.
#![no_std]

use embedded_cal::{Cal, HashProvider, plumbing::Plumbing};
use libcrux_sha2::Digest;

pub trait ExtenderConfig {
    const IMPLEMENT_SHA2SHORT: bool;

    type Base: Cal + Plumbing;
}

impl<EC: ExtenderConfig> Extender<EC> {
    pub fn new(base: EC::Base) -> Self {
        Self(base)
    }
}

pub struct Extender<EC: ExtenderConfig>(EC::Base);

impl<EC: ExtenderConfig> Cal for Extender<EC> {}

pub struct Sha256State(libcrux_sha2::Sha256);

pub enum HashState<EC: ExtenderConfig> {
    Direct(<EC::Base as HashProvider>::HashState),
    Sha256(Sha256State),
}

impl<EC: ExtenderConfig> HashProvider for Extender<EC> {
    type Algorithm = HashAlgorithm<EC>;

    type HashState = HashState<EC>;

    type HashResult = HashResult<EC>;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {
            HashAlgorithm::Sha256 => HashState::Sha256(Sha256State(libcrux_sha2::Sha256::new())),
            HashAlgorithm::Direct(alg) => HashState::Direct(HashProvider::init(&mut self.0, alg)),
        }
    }

    fn update(&mut self, instance: &mut Self::HashState, data: &[u8]) {
        match instance {
            HashState::Direct(i) => HashProvider::update(&mut self.0, i, data),
            HashState::Sha256(s) => s.0.update(data),
        }
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {
            HashState::Direct(underlying) => {
                HashResult::Direct(HashProvider::finalize(&mut self.0, underlying))
            }
            HashState::Sha256(s) => {
                let mut output = [0u8; 32];
                s.0.finish(&mut output);
                HashResult::Sha256(output)
            }
        }
    }
}

pub enum HashAlgorithm<EC: ExtenderConfig> {
    // FIXME: Ideally we'd employ some witness type of <EC::Base as Sha2Short>::SUPPORTED
    // to render this uninhabited when unused.
    Sha256,
    Direct(<EC::Base as HashProvider>::Algorithm),
}

// Seems the Derive wouldn't take because it only looks at whether all arguments are Clone, not at
// whether the parts of the arguments that are used are. Could be replaced by some
// derive-stuff-more-smartly crate.
impl<EC: ExtenderConfig> Clone for HashAlgorithm<EC> {
    fn clone(&self) -> Self {
        match self {
            HashAlgorithm::Sha256 => HashAlgorithm::Sha256,
            HashAlgorithm::Direct(a) => HashAlgorithm::Direct(a.clone()),
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> core::fmt::Debug for HashAlgorithm<EC> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "Sha256"),
            HashAlgorithm::Direct(arg0) => f.debug_tuple("Direct").field(arg0).finish(),
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> PartialEq for HashAlgorithm<EC> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (HashAlgorithm::Direct(l0), HashAlgorithm::Direct(r0)) => l0 == r0,
            (HashAlgorithm::Sha256, HashAlgorithm::Sha256) => true,
            _ => false,
        }
    }
}

// As for Clone
impl<EC: ExtenderConfig> Eq for HashAlgorithm<EC> {}

impl<EC: ExtenderConfig> embedded_cal::HashAlgorithm for HashAlgorithm<EC> {
    fn len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Direct(a) => a.len(),
        }
    }

    #[inline]
    fn from_cose_number(number: impl Into<i128>) -> Option<Self> {
        let number: i128 = number.into();

        match number {
            -16 => Some(HashAlgorithm::Sha256),
            _ => <EC::Base as HashProvider>::Algorithm::from_cose_number(number)
                .map(HashAlgorithm::Direct),
        }
    }

    #[inline]
    fn from_ni_id(number: u8) -> Option<Self> {
        match number {
            1 => Self::from_cose_number(-16),
            _ => None,
        }
    }

    #[inline]
    fn from_ni_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Self::from_cose_number(-16),
            _ => None,
        }
    }
}

pub enum HashResult<EC: ExtenderConfig> {
    Sha256([u8; 32]),
    Direct(<EC::Base as HashProvider>::HashResult),
}

impl<EC: ExtenderConfig> AsRef<[u8]> for HashResult<EC> {
    fn as_ref(&self) -> &[u8] {
        match self {
            HashResult::Sha256(data) => data.as_slice(),
            HashResult::Direct(result) => result.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod dummy_sha256;

    struct TestConfig;

    impl ExtenderConfig for TestConfig {
        const IMPLEMENT_SHA2SHORT: bool = false;
        type Base = dummy_sha256::LibcruxSha256;
    }

    #[test]
    fn test_hash_algorithm_sha256() {
        let mut cal = Extender::<TestConfig>::new(dummy_sha256::LibcruxSha256);

        testvectors::test_hash_algorithm_sha256(&mut cal);
    }
}
