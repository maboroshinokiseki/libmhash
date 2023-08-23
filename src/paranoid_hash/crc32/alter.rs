use std::mem::size_of;

use crate::{paranoid_hash::Hasher, Error, Result};

#[derive(Clone, Debug, Default)]
pub struct CRC32 {
    state: crc32fast::Hasher,
    is_done: bool,
    digest: [u8; 4],
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct CRC32C {
    state: u32,
    is_done: bool,
    digest: [u8; 4],
}

impl CRC32 {
    pub const BLOCK_SIZE: usize = 1;
    pub const DIGEST_SIZE: usize = size_of::<u32>();

    pub fn new() -> Self {
        Self {
            state: crc32fast::Hasher::new(),
            digest: [0; 4],
            is_done: false,
        }
    }
}

impl Hasher for CRC32 {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_done {
            return Err(Error::UpdatingAfterFinished);
        }

        self.state.update(data);

        Ok(())
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)?;

        self.digest = self.state.clone().finalize().to_be_bytes();

        self.is_done = true;

        Ok(())
    }

    fn digest(&self) -> Result<&[u8]> {
        if !self.is_done {
            return Err(Error::NotFinished);
        }

        Ok(&self.digest)
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}

impl CRC32C {
    pub const BLOCK_SIZE: usize = 1;
    pub const DIGEST_SIZE: usize = size_of::<u32>();

    pub const fn new() -> Self {
        Self {
            state: 0,
            digest: [0; 4],
            is_done: false,
        }
    }
}

impl Hasher for CRC32C {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_done {
            return Err(Error::UpdatingAfterFinished);
        }

        self.state = crc32c::crc32c_append(self.state, data);

        Ok(())
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)?;

        self.digest = self.state.to_be_bytes();

        self.is_done = true;

        Ok(())
    }

    fn digest(&self) -> Result<&[u8]> {
        if !self.is_done {
            return Err(Error::NotFinished);
        }

        Ok(&self.digest)
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}
