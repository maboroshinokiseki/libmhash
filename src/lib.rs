pub mod hasher_server;
pub mod paranoid_hash;

pub use error::*;

mod error;
mod simple_semaphore;
mod tag_thread_pool;

pub mod prelude {
    pub use crate::{
        hasher_server::{
            Builder, BuilderTrait, HasherError, HasherProgress, HasherResult, HasherServer,
            HasherServerTrait, HasherWrapper,
        },
        paranoid_hash::HasherTag,
    };
}
