use sha2::Digest;

use crate::{paranoid_hash::Hasher, Error, Result};

macro_rules! create_sha2 {
    ( $struct:ident, $base:ty, $bs:expr, $ds:expr ) => {
        #[derive(Clone, Debug)]
        pub struct $struct {
            state: $base,
            is_done: bool,
            digest: [u8; Self::DIGEST_SIZE],
        }

        impl $struct {
            pub const BLOCK_SIZE: usize = $bs;
            pub const DIGEST_SIZE: usize = $ds;

            pub fn new() -> Self {
                Self {
                    state: <$base>::new(),
                    is_done: false,
                    digest: [0; Self::DIGEST_SIZE],
                }
            }
        }

        impl Hasher for $struct {
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
                *self = Self::new()
            }

            fn block_size(&self) -> usize {
                Self::BLOCK_SIZE
            }

            fn digest_size(&self) -> usize {
                Self::DIGEST_SIZE
            }
        }

        impl Default for $struct {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

create_sha2!(SHA2_224, sha2::Sha224, super::SHA256_BLOCK_SIZE, 224 / 8);

create_sha2!(SHA2_256, sha2::Sha256, super::SHA256_BLOCK_SIZE, 256 / 8);

create_sha2!(SHA2_384, sha2::Sha384, super::SHA512_BLOCK_SIZE, 384 / 8);

create_sha2!(SHA2_512, sha2::Sha512, super::SHA512_BLOCK_SIZE, 512 / 8);
