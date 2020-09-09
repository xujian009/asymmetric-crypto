use alloc::vec::Vec;
use core::fmt::Debug;
use libsm::sm3::hash::Sm3Hash;

#[derive(Clone)]
pub struct Sm3(Vec<u8>);

impl Debug for Sm3 {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

impl Default for Sm3 {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl dislog_hal::Hasher for Sm3 {
    type Output = [u8; 32];

    fn update(&mut self, data: impl AsRef<[u8]>) {
        let o = Vec::from(data.as_ref());
        self.0.extend(o);
    }

    fn finalize(self) -> Self::Output {
        let mut hasher = Sm3Hash::new(&self.0[..]);
        hasher.get_hash()
    }
}
