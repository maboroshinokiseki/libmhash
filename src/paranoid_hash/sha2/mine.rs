use std::{mem::size_of, ops::Shr};

use ambassador::Delegate;

use super::{SHA256_BLOCK_SIZE, SHA512_BLOCK_SIZE};
use crate::{paranoid_hash::Hasher, Error, Result};

macro_rules! impl_common {
    ( $struct:ty, $base:ty ) => {
        impl $struct {
            pub const BLOCK_SIZE: usize = <$base>::BLOCK_SIZE;
            pub const DIGEST_SIZE: usize = <$base>::DIGEST_SIZE;

            pub const fn new() -> Self {
                Self(<$base>::new())
            }
        }
    };
}

macro_rules! update_block {
    ( $self:expr, $block:expr, $round:expr, $k:expr ) => {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = $self.state;

        let mut words: [Self::Word; $round] = [0; $round];
        words[0..$block.len()].copy_from_slice($block);
        for i in $block.len()..$round {
            words[i] = Self::ssigma1(words[i - 2])
                .wrapping_add(words[i - 7])
                .wrapping_add(Self::ssigma0(words[i - 15]))
                .wrapping_add(words[i - 16]);
        }

        for i in 0..$round {
            let t1 = h
                .wrapping_add(Self::bsigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add($k[i])
                .wrapping_add(words[i]);
            let t2 = Self::bsigma0(a).wrapping_add(Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        $self.state[0] = a.wrapping_add($self.state[0]);
        $self.state[1] = b.wrapping_add($self.state[1]);
        $self.state[2] = c.wrapping_add($self.state[2]);
        $self.state[3] = d.wrapping_add($self.state[3]);
        $self.state[4] = e.wrapping_add($self.state[4]);
        $self.state[5] = f.wrapping_add($self.state[5]);
        $self.state[6] = g.wrapping_add($self.state[6]);
        $self.state[7] = h.wrapping_add($self.state[7]);
    };
}

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_224(SHA2_256Core<224>);
impl_common!(SHA2_224, SHA2_256Core<224>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_256(SHA2_256Core<256>);
impl_common!(SHA2_256, SHA2_256Core<256>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_384(SHA2_512Core<384>);
impl_common!(SHA2_384, SHA2_512Core<384>);

#[derive(Delegate, Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[delegate(Hasher)]
pub struct SHA2_512(SHA2_512Core<512>);
impl_common!(SHA2_512, SHA2_512Core<512>);

trait SHA2Core {
    type Word;
    type Count;

    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;
    const INITIAL_STATE: [Self::Word; STATE_SIZE_IN_WORD];

    fn ch(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word;
    fn maj(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word;
    fn bsigma0(x: Self::Word) -> Self::Word;
    fn bsigma1(x: Self::Word) -> Self::Word;
    fn ssigma0(x: Self::Word) -> Self::Word;
    fn ssigma1(x: Self::Word) -> Self::Word;
    fn update_block(&mut self, block: &[Self::Word; BLOCK_SIZE_IN_WORD]);
}

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct SHA2_256Core<const LENGTH: usize> {
    state: [u32; STATE_SIZE_IN_WORD],
    count: u64,
    is_done: bool,
    digest: [u8; SHA256_DIGEST_SIZE],
}

impl<const LENGTH: usize> SHA2_256Core<LENGTH> {
    const fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            count: 0,
            is_done: false,
            digest: [0u8; SHA256_DIGEST_SIZE],
        }
    }
}

impl<const LENGTH: usize> SHA2Core for SHA2_256Core<LENGTH> {
    type Word = u32;

    type Count = u64;

    const BLOCK_SIZE: usize = SHA256_BLOCK_SIZE;

    const DIGEST_SIZE: usize = LENGTH / 8;

    const INITIAL_STATE: [Self::Word; STATE_SIZE_IN_WORD] = match LENGTH {
        224 => SHA224_INITIAL,
        256 => SHA256_INITIAL,
        _ => panic!("Invalid length"),
    };

    #[inline]
    fn ch(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y ^ z)) ^ z
    }

    #[inline]
    fn maj(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y | z)) | (y & z)
    }

    #[inline]
    fn bsigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline]
    fn bsigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline]
    fn ssigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(7) ^ x.rotate_right(18) ^ x.shr(3)
    }

    #[inline]
    fn ssigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(17) ^ x.rotate_right(19) ^ x.shr(10)
    }

    #[inline]
    fn update_block(&mut self, block: &[Self::Word; BLOCK_SIZE_IN_WORD]) {
        update_block!(self, block, SHA256_ROUND_COUNT, K256);
    }
}

impl<const LENGTH: usize> Hasher for SHA2_256Core<LENGTH> {
    #[inline]
    fn update(&mut self, data: &[u8]) -> Result<()> {
        transmute_update!(self, data, SHA256_BLOCK_SIZE, u32, u64, "checked", "be");
    }

    #[inline]
    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        transmute_update_last!(self, data, SHA256_BLOCK_SIZE, u32, u64, "checked", "be");
    }

    #[inline]
    fn digest(&self) -> Result<&[u8]> {
        if !self.is_done {
            return Err(Error::NotFinished);
        }

        Ok(&self.digest[..Self::DIGEST_SIZE])
    }

    #[inline]
    fn reset(&mut self) {
        *self = Self::new();
    }

    #[inline]
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    #[inline]
    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct SHA2_512Core<const LENGTH: usize> {
    state: [u64; STATE_SIZE_IN_WORD],
    count: u128,
    is_done: bool,
    digest: [u8; SHA512_DIGEST_SIZE],
}

impl<const LENGTH: usize> SHA2_512Core<LENGTH> {
    const fn new() -> Self {
        Self {
            state: Self::INITIAL_STATE,
            count: 0,
            is_done: false,
            digest: [0u8; SHA512_DIGEST_SIZE],
        }
    }
}

impl<const LENGTH: usize> SHA2Core for SHA2_512Core<LENGTH> {
    type Word = u64;

    type Count = u128;

    const BLOCK_SIZE: usize = SHA512_BLOCK_SIZE;

    const DIGEST_SIZE: usize = LENGTH / 8;

    const INITIAL_STATE: [Self::Word; STATE_SIZE_IN_WORD] = match LENGTH {
        384 => SHA384_INITIAL,
        512 => SHA512_INITIAL,
        _ => panic!("Invalid length"),
    };

    #[inline]
    fn ch(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y ^ z)) ^ z
    }

    #[inline]
    fn maj(x: Self::Word, y: Self::Word, z: Self::Word) -> Self::Word {
        (x & (y | z)) | (y & z)
    }

    #[inline]
    fn bsigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline]
    fn bsigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline]
    fn ssigma0(x: Self::Word) -> Self::Word {
        x.rotate_right(1) ^ x.rotate_right(8) ^ x.shr(7)
    }

    #[inline]
    fn ssigma1(x: Self::Word) -> Self::Word {
        x.rotate_right(19) ^ x.rotate_right(61) ^ x.shr(6)
    }

    #[inline]
    fn update_block(&mut self, block: &[Self::Word; BLOCK_SIZE_IN_WORD]) {
        update_block!(self, block, SHA512_ROUND_COUNT, K512);
    }
}

impl<const LENGTH: usize> Hasher for SHA2_512Core<LENGTH> {
    #[inline]
    fn update(&mut self, data: &[u8]) -> Result<()> {
        transmute_update!(self, data, SHA512_BLOCK_SIZE, u64, u128, "checked", "be");
    }

    #[inline]
    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        transmute_update_last!(self, data, SHA512_BLOCK_SIZE, u64, u128, "checked", "be");
    }

    #[inline]
    fn digest(&self) -> Result<&[u8]> {
        if !self.is_done {
            return Err(Error::NotFinished);
        }

        Ok(&self.digest[..Self::DIGEST_SIZE])
    }

    #[inline]
    fn reset(&mut self) {
        *self = Self::new();
    }

    #[inline]
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    #[inline]
    fn digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}

impl<const LENGTH: usize> Default for SHA2_512Core<LENGTH> {
    fn default() -> Self {
        Self::new()
    }
}

const STATE_SIZE_IN_WORD: usize = 8;
const BLOCK_SIZE_IN_WORD: usize = 16;
const SHA256_DIGEST_SIZE: usize = 256 / 8;
const SHA512_DIGEST_SIZE: usize = 512 / 8;
const SHA256_ROUND_COUNT: usize = 64;
const SHA512_ROUND_COUNT: usize = 80;

const SHA224_INITIAL: [u32; STATE_SIZE_IN_WORD] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

const SHA256_INITIAL: [u32; STATE_SIZE_IN_WORD] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA384_INITIAL: [u64; STATE_SIZE_IN_WORD] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

const SHA512_INITIAL: [u64; STATE_SIZE_IN_WORD] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const K256: [u32; SHA256_ROUND_COUNT] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K512: [u64; SHA512_ROUND_COUNT] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];
