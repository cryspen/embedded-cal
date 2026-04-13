//! Minimal base type that satisfies the [`ExtenderConfig::Base`] bounds for use in unit tests.
//!
//! The [`Extender`] now handles SHA-256 entirely via libcrux-sha2, so this base type only needs
//! to implement the required traits — none of the `Sha2Short` methods are ever called.

use embedded_cal::plumbing::hash::{Sha2Short, Sha2ShortVariant};

pub struct LibcruxSha256;

impl embedded_cal::Cal for LibcruxSha256 {}

impl embedded_cal::HashProvider for LibcruxSha256 {
    type Algorithm = embedded_cal::NoHashAlgorithms;
    type HashState = embedded_cal::NoHashAlgorithms;
    type HashResult = embedded_cal::NoHashAlgorithms;

    fn init(&mut self, algorithm: Self::Algorithm) -> Self::HashState {
        match algorithm {}
    }

    fn update(&mut self, instance: &mut Self::HashState, _data: &[u8]) {
        match *instance {}
    }

    fn finalize(&mut self, instance: Self::HashState) -> Self::HashResult {
        match instance {}
    }
}

impl embedded_cal::plumbing::Plumbing for LibcruxSha256 {}

impl embedded_cal::plumbing::hash::Hash for LibcruxSha256 {}

impl Sha2Short for LibcruxSha256 {
    const SUPPORTED: bool = false;
    const SEND_PADDING: bool = false;
    const FIRST_CHUNK_SIZE: usize = 0;
    const UPDATE_MULTICHUNK: bool = false;

    type State = ();

    fn init(&mut self, _variant: Sha2ShortVariant) -> Self::State {
        unimplemented!("Sha2Short not used — Extender handles SHA-256 via libcrux-sha2 directly")
    }

    fn update(&mut self, _instance: &mut Self::State, _data: &[u8]) {
        unimplemented!("Sha2Short not used — Extender handles SHA-256 via libcrux-sha2 directly")
    }

    fn finalize(&mut self, _instance: Self::State, _last_chunk: &[u8], _target: &mut [u8]) {
        unimplemented!("Sha2Short not used — Extender handles SHA-256 via libcrux-sha2 directly")
    }
}
