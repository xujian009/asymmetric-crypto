use core::fmt::Debug;
use hex::{FromHex, ToHex};

pub trait Splitable {
    type Half: Debug + ToHex + FromHex + PartialEq;

    fn split_finalize(self) -> (Self::Half, Self::Half);
}
