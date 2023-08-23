use std::mem::size_of;

use crate::{paranoid_hash::Hasher, Error, Result};

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MD4 {
    state: [u32; 4],
    count: u64,
    is_done: bool,
    digest: [u8; Self::DIGEST_SIZE],
}

impl Hasher for MD4 {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        transmute_update!(self, data, Self::BLOCK_SIZE, u32, u64, "wrapping", "le");
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        transmute_update_last!(self, data, Self::BLOCK_SIZE, u32, u64, "wrapping", "le");
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

impl MD4 {
    pub const BLOCK_SIZE: usize = 64;
    pub const DIGEST_SIZE: usize = 16;

    const U32_BLOCK_SIZE: usize = Self::BLOCK_SIZE / size_of::<u32>();

    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            is_done: false,
            digest: [0; Self::DIGEST_SIZE],
        }
    }

    #[inline]
    fn update_block(&mut self, block: &[u32; Self::U32_BLOCK_SIZE]) {
        let [mut a, mut b, mut c, mut d] = self.state;

        a = round_1(a, b, c, d, block[0], S11);
        d = round_1(d, a, b, c, block[1], S12);
        c = round_1(c, d, a, b, block[2], S13);
        b = round_1(b, c, d, a, block[3], S14);
        a = round_1(a, b, c, d, block[4], S11);
        d = round_1(d, a, b, c, block[5], S12);
        c = round_1(c, d, a, b, block[6], S13);
        b = round_1(b, c, d, a, block[7], S14);
        a = round_1(a, b, c, d, block[8], S11);
        d = round_1(d, a, b, c, block[9], S12);
        c = round_1(c, d, a, b, block[10], S13);
        b = round_1(b, c, d, a, block[11], S14);
        a = round_1(a, b, c, d, block[12], S11);
        d = round_1(d, a, b, c, block[13], S12);
        c = round_1(c, d, a, b, block[14], S13);
        b = round_1(b, c, d, a, block[15], S14);

        a = round_2(a, b, c, d, block[0], S21);
        d = round_2(d, a, b, c, block[4], S22);
        c = round_2(c, d, a, b, block[8], S23);
        b = round_2(b, c, d, a, block[12], S24);
        a = round_2(a, b, c, d, block[1], S21);
        d = round_2(d, a, b, c, block[5], S22);
        c = round_2(c, d, a, b, block[9], S23);
        b = round_2(b, c, d, a, block[13], S24);
        a = round_2(a, b, c, d, block[2], S21);
        d = round_2(d, a, b, c, block[6], S22);
        c = round_2(c, d, a, b, block[10], S23);
        b = round_2(b, c, d, a, block[14], S24);
        a = round_2(a, b, c, d, block[3], S21);
        d = round_2(d, a, b, c, block[7], S22);
        c = round_2(c, d, a, b, block[11], S23);
        b = round_2(b, c, d, a, block[15], S24);

        a = round_3(a, b, c, d, block[0], S31);
        d = round_3(d, a, b, c, block[8], S32);
        c = round_3(c, d, a, b, block[4], S33);
        b = round_3(b, c, d, a, block[12], S34);
        a = round_3(a, b, c, d, block[2], S31);
        d = round_3(d, a, b, c, block[10], S32);
        c = round_3(c, d, a, b, block[6], S33);
        b = round_3(b, c, d, a, block[14], S34);
        a = round_3(a, b, c, d, block[1], S31);
        d = round_3(d, a, b, c, block[9], S32);
        c = round_3(c, d, a, b, block[5], S33);
        b = round_3(b, c, d, a, block[13], S34);
        a = round_3(a, b, c, d, block[3], S31);
        d = round_3(d, a, b, c, block[11], S32);
        c = round_3(c, d, a, b, block[7], S33);
        b = round_3(b, c, d, a, block[15], S34);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

#[inline(always)]
fn hash_1(x: u32, y: u32, z: u32) -> u32 {
    x & y | !x & z
}

#[inline(always)]
fn hash_2(x: u32, y: u32, z: u32) -> u32 {
    x & y | x & z | y & z
}

#[inline(always)]
fn hash_3(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn round_1(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    hash_1(b, c, d)
        .wrapping_add(x)
        .wrapping_add(a)
        .rotate_left(s)
}

#[inline(always)]
fn round_2(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    hash_2(b, c, d)
        .wrapping_add(x)
        .wrapping_add(a)
        .wrapping_add(0x5a827999)
        .rotate_left(s)
}

#[inline(always)]
fn round_3(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
    hash_3(b, c, d)
        .wrapping_add(x)
        .wrapping_add(a)
        .wrapping_add(0x6ed9eba1)
        .rotate_left(s)
}

const S11: u32 = 3;
const S12: u32 = 7;
const S13: u32 = 11;
const S14: u32 = 19;
const S21: u32 = 3;
const S22: u32 = 5;
const S23: u32 = 9;
const S24: u32 = 13;
const S31: u32 = 3;
const S32: u32 = 9;
const S33: u32 = 11;
const S34: u32 = 15;

#[cfg(test)]
mod tests {
    use crate::paranoid_hash::{
        tester::{HasherTestWrapper, TestData},
        Hasher,
    };

    use super::MD4;

    const TESTS: &[TestData] = &[
        TestData {
            data: "".as_bytes(),
            repeat: 1,
            result: "31d6cfe0d16ae931b73c59d7e0c089c0",
        },
        TestData {
            data: "a".as_bytes(),
            repeat: 1,
            result: "bde52cb31de33e46245e05fbdbd6fb24",
        },
        TestData {
            data: "abc".as_bytes(),
            repeat: 1,
            result: "a448017aaf21d8525fc10ae87aa6729d",
        },
        TestData {
            data: "message digest".as_bytes(),
            repeat: 1,
            result: "d9130a8164549fe818874806e1c7014b",
        },
        TestData {
            data: "abcdefghijklmnopqrstuvwxyz".as_bytes(),
            repeat: 1,
            result: "d79e1c308aa5bbcdeea8ed63df412da9",
        },
        TestData {
            data: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_bytes(),
            repeat: 1,
            result: "043f8582f241db351ce627e153e7f0e4",
        },
        TestData {
            data:
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                    .as_bytes(),
            repeat: 1,
            result: "e33b4ddc9c38f2199c3e7b164fcc0536",
        },
    ];

    #[test]
    fn tests_from_rfc() {
        HasherTestWrapper::new(MD4::new()).run_tests(TESTS);
    }

    #[test]
    #[should_panic]
    fn panic_test1() {
        let mut hasher = MD4::new();
        hasher
            .update("Not multiple of block size".as_bytes())
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn panic_test2() {
        let mut hasher = MD4::new();
        let data = [0u8; MD4::BLOCK_SIZE + 1];
        hasher.update_last(&data).unwrap();
    }
}
