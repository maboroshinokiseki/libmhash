#![allow(dead_code)]
#![cfg(test)]

use super::Hasher;

pub(super) struct HasherTestWrapper<Base: Hasher> {
    base: Base,
    cache: Vec<u8>,
}

impl<Base: Hasher> HasherTestWrapper<Base> {
    pub fn new(base: Base) -> Self {
        Self {
            base,
            cache: vec![],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for byte in data {
            self.cache.push(*byte);
            if self.cache.len() == self.base.block_size() {
                self.base.update(&self.cache).unwrap();
                self.cache.clear();
            }
        }
    }

    pub fn finalize(&mut self) -> &[u8] {
        self.base.update_last(&self.cache).unwrap();
        self.base.digest().unwrap()
    }

    pub fn reset(&mut self) {
        self.base.reset();
        self.cache.clear();
    }

    pub fn finalize_reset(&mut self) -> Vec<u8> {
        let digest = Vec::from(self.finalize());
        self.reset();
        digest
    }

    pub fn run_tests(&mut self, tests: &[TestData]) {
        for test in tests {
            for _ in 0..test.repeat {
                self.update(test.data);
            }
            assert_eq!(hex::encode(self.finalize()), test.result);
            self.reset();
        }
    }
}

pub(super) struct TestData<'a> {
    pub data: &'a [u8],
    pub repeat: usize,
    pub result: &'a str,
}
