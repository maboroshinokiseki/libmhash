use std::mem::size_of;

use crate::{paranoid_hash::Hasher, Error, Result};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
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
    pub const BLOCK_SIZE: usize = 64;
    pub const DIGEST_SIZE: usize = 20;

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

#[cfg(test)]
mod tests {
    use crate::paranoid_hash::{
        tester::{HasherTestWrapper, TestData},
        Hasher,
    };

    use super::SHA1;

    const TESTS: &[TestData] = &[
        TestData {
            data: "abc".as_bytes(),
            repeat: 1,
            result: "a9993e364706816aba3e25717850c26c9cd0d89d",
        },
        TestData {
            data: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(),
            repeat: 1,
            result: "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        },
        TestData {
            data: "a".as_bytes(),
            repeat: 1000000,
            result: "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
        },
        TestData {
            data: "0123456701234567012345670123456701234567012345670123456701234567".as_bytes(),
            repeat: 10,
            result: "dea356a2cddd90c7a7ecedc5ebb563934f460452",
        },
        TestData {
            data: &[0x5e],
            repeat: 1,
            result: "5e6f80a34a9798cafc6a5db96cc57ba4c4db59c2",
        },
        TestData {
            data: &[
                0x9a, 0x7d, 0xfd, 0xf1, 0xec, 0xea, 0xd0, 0x6e, 0xd6, 0x46, 0xaa, 0x55, 0xfe, 0x75,
                0x71, 0x46,
            ],
            repeat: 1,
            result: "82abff6605dbe1c17def12a394fa22a82b544a35",
        },
        TestData {
            data: &[
                0xf7, 0x8f, 0x92, 0x14, 0x1b, 0xcd, 0x17, 0x0a, 0xe8, 0x9b, 0x4f, 0xba, 0x15, 0xa1,
                0xd5, 0x9f, 0x3f, 0xd8, 0x4d, 0x22, 0x3c, 0x92, 0x51, 0xbd, 0xac, 0xbb, 0xae, 0x61,
                0xd0, 0x5e, 0xd1, 0x15, 0xa0, 0x6a, 0x7c, 0xe1, 0x17, 0xb7, 0xbe, 0xea, 0xd2, 0x44,
                0x21, 0xde, 0xd9, 0xc3, 0x25, 0x92, 0xbd, 0x57, 0xed, 0xea, 0xe3, 0x9c, 0x39, 0xfa,
                0x1f, 0xe8, 0x94, 0x6a, 0x84, 0xd0, 0xcf, 0x1f, 0x7b, 0xee, 0xad, 0x17, 0x13, 0xe2,
                0xe0, 0x95, 0x98, 0x97, 0x34, 0x7f, 0x67, 0xc8, 0x0b, 0x04, 0x00, 0xc2, 0x09, 0x81,
                0x5d, 0x6b, 0x10, 0xa6, 0x83, 0x83, 0x6f, 0xd5, 0x56, 0x2a, 0x56, 0xca, 0xb1, 0xa2,
                0x8e, 0x81, 0xb6, 0x57, 0x66, 0x54, 0x63, 0x1c, 0xf1, 0x65, 0x66, 0xb8, 0x6e, 0x3b,
                0x33, 0xa1, 0x08, 0xb0, 0x53, 0x07, 0xc0, 0x0a, 0xff, 0x14, 0xa7, 0x68, 0xed, 0x73,
                0x50, 0x60, 0x6a, 0x0f, 0x85, 0xe6, 0xa9, 0x1d, 0x39, 0x6f, 0x5b, 0x5c, 0xbe, 0x57,
                0x7f, 0x9b, 0x38, 0x80, 0x7c, 0x7d, 0x52, 0x3d, 0x6d, 0x79, 0x2f, 0x6e, 0xbc, 0x24,
                0xa4, 0xec, 0xf2, 0xb3, 0xa4, 0x27, 0xcd, 0xbb, 0xfb,
            ],
            repeat: 1,
            result: "cb0082c8f197d260991ba6a460e76e202bad27b3",
        },
    ];

    #[test]
    fn tests_from_rfc() {
        HasherTestWrapper::new(SHA1::new()).run_tests(TESTS);
    }

    #[test]
    #[should_panic]
    fn panic_test1() {
        let mut hasher = SHA1::new();
        hasher
            .update("Not multiple of block size".as_bytes())
            .unwrap();
    }

    #[test]
    #[should_panic]
    fn panic_test2() {
        let mut hasher = SHA1::new();
        let data = [0u8; SHA1::BLOCK_SIZE + 1];
        hasher.update_last(&data).unwrap();
    }
}
