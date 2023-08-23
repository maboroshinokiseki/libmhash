use sha1::Digest;

use crate::{paranoid_hash::Hasher, Error, Result};

use super::{SHA1_BLOCK_SIZE, SHA1_DIGEST_SIZE};

#[derive(Clone, Debug, Default)]
pub struct SHA1 {
    state: sha1::Sha1,
    is_done: bool,
    digest: [u8; Self::DIGEST_SIZE],
}

impl Hasher for SHA1 {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_done {
            return Err(Error::UpdatingAfterFinished);
        }

        self.state.update(data);
        Ok(())
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        if self.is_done {
            return Err(Error::UpdatingAfterFinished);
        }

        self.is_done = true;

        self.state.update(data);
        let state = self.state.clone();
        let digest = state.finalize();
        self.digest.copy_from_slice(&digest[..]);
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

impl SHA1 {
    pub const BLOCK_SIZE: usize = SHA1_BLOCK_SIZE;
    pub const DIGEST_SIZE: usize = SHA1_DIGEST_SIZE;

    pub fn new() -> Self {
        Self {
            state: sha1::Sha1::new(),
            is_done: false,
            digest: [0; Self::DIGEST_SIZE],
        }
    }
}
