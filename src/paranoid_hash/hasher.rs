#![macro_use]

use ambassador::delegatable_trait;

use crate::Result;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum HasherTag {
    CRC32,
    CRC32C,
    MD2,
    MD4,
    MD5,
    SHA1,
    SHA2_224,
    SHA2_256,
    SHA2_384,
    SHA2_512,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

#[delegatable_trait]
pub trait Hasher {
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn update_last(&mut self, data: &[u8]) -> Result<()>;
    fn digest(&self) -> Result<&[u8]>;
    fn reset(&mut self);

    fn block_size(&self) -> usize;
    fn digest_size(&self) -> usize;
}
