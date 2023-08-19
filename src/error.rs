use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Data length overflowed, maximum allow data length is {0}")]
    DataLengthOverflowed(u128),
    #[error("Data length was not a multiple of block size, data length: {0}, block size: {1}")]
    DataLengthMismatched(usize, usize),
    #[error("Data length was larger than block size, data length: {0}, block size: {1}")]
    DataTooLarge(usize, usize),
    #[error("Trying to get digest before calling udpate_last")]
    NotFinished,
    #[error("Calling update after hasher finished")]
    UpdatingAfterFinished,
    #[error("Block size given was not a multiple of base block size. Which is 128.")]
    IncorrectBlockSize,
    #[error("Io Error.")]
    IoError(#[from] std::io::Error),
    #[error("Data ended already! No more new id is allowed!")]
    DataEnded,
}

pub type Result<T> = std::result::Result<T, Error>;
