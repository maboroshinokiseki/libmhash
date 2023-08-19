use std::sync::Arc;

use crate::{
    hasher_server::{sync_unsafe_cell::SyncUnsafeCell, Identifier},
    simple_semaphore::SimpleSemaphore,
};

#[derive(Debug)]
pub(super) struct DataWrapper {
    pub identifier: Identifier,
    //block_semaphore will prevent data race
    pub data: Arc<SyncUnsafeCell<Vec<u8>>>,
    pub semaphore: Arc<SimpleSemaphore>,
    pub length: usize,
    pub last: bool,
    pub total_data_length: u64,
    pub sent_data_length: u64,
}

impl Drop for DataWrapper {
    fn drop(&mut self) {
        self.semaphore.release();
    }
}
