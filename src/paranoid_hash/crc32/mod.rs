cfg_if::cfg_if! {
    if #[cfg(feature = "alter-impl")] {
        mod alter;
        pub use alter::*;
    } else {
        mod mine;
        pub use self::mine::*;
    }
}

#[cfg(test)]
mod tests {
    use crate::paranoid_hash::tester::{HasherTestWrapper, TestData};

    use super::CRC32;
    use super::CRC32C;

    const CRC32_TESTS: &[TestData] = &[TestData {
        data: "123456789".as_bytes(),
        repeat: 1,
        result: "cbf43926",
    }];

    const CRC32C_TESTS: &[TestData] = &[TestData {
        data: "123456789".as_bytes(),
        repeat: 1,
        result: "e3069283",
    }];

    #[test]
    fn tests() {
        HasherTestWrapper::new(CRC32::new()).run_tests(CRC32_TESTS);

        HasherTestWrapper::new(CRC32C::new()).run_tests(CRC32C_TESTS);
    }
}
