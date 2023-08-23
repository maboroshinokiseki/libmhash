use std::mem::size_of;

use super::{SHA1_BLOCK_SIZE, SHA1_DIGEST_SIZE};
use crate::{paranoid_hash::Hasher, Error, Result};

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SHA1 {
    state: [u32; Self::U32_DIGEST_SIZE],
    count: u64,
    is_done: bool,
    digest: [u8; Self::DIGEST_SIZE],
}

impl Hasher for SHA1 {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        transmute_update!(self, data, Self::BLOCK_SIZE, u32, u64, "checked", "be");
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        transmute_update_last!(self, data, Self::BLOCK_SIZE, u32, u64, "checked", "be");
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

    const U32_BLOCK_SIZE: usize = Self::BLOCK_SIZE / size_of::<u32>();
    const U32_DIGEST_SIZE: usize = Self::DIGEST_SIZE / size_of::<u32>();

    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            count: 0,
            is_done: false,
            digest: [0; Self::DIGEST_SIZE],
        }
    }

    #[inline]
    fn update_block(&mut self, block: &[u32; Self::U32_BLOCK_SIZE]) {
        let mut w = [0u32; 80];
        w[0..block.len()].copy_from_slice(block);

        for i in block.len()..w.len() {
            let temp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = temp.rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for w in w.iter().take(20) {
            let temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | (!b & d))
                .wrapping_add(e)
                .wrapping_add(*w)
                .wrapping_add(K[0]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for w in w.iter().skip(20).take(20) {
            let temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(*w)
                .wrapping_add(K[1]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for w in w.iter().skip(40).take(20) {
            let temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(e)
                .wrapping_add(*w)
                .wrapping_add(K[2]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for w in w.iter().skip(60).take(20) {
            let temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(*w)
                .wrapping_add(K[3]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
