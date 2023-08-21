use std::{hash::Hash, sync::Arc};

use crossbeam_channel::Sender;

use crate::{
    hasher_server::{
        data_wrapper::DataWrapper, operation::Operation, sync_unsafe_cell::SyncUnsafeCell,
        HasherError, Identifier,
    },
    simple_semaphore::SimpleSemaphore,
    Error,
};

#[derive(Debug)]
pub struct FragmentSender<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub(super) id: Identifier,
    pub(super) length: u64,
    pub(super) sent_length: u64,
    pub(super) block_size: usize,
    pub(super) operation_sender: Sender<Operation<Tag>>,
    pub(super) id_semaphore: Arc<SimpleSemaphore>,
    pub(super) block_semaphore: Arc<SimpleSemaphore>,
}

impl<Tag> FragmentSender<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub fn set_data_length(&mut self, length: u64) {
        self.length = length;
    }

    pub fn push_data(&mut self, buffer: &[u8]) {
        if buffer.len() != self.block_size {
            self.operation_sender
                .send(Operation::Error(HasherError {
                    identifier: self.id.clone(),
                    tag: None,
                    error: Error::DataLengthMismatched(buffer.len(), self.block_size),
                }))
                .unwrap();
            return;
        }
        self.push_data_inner(buffer, false);
    }

    pub fn push_last_data(mut self, buffer: &[u8]) {
        if buffer.len() > self.block_size {
            self.operation_sender
                .send(Operation::Error(HasherError {
                    identifier: self.id.clone(),
                    tag: None,
                    error: Error::DataTooLarge(buffer.len(), self.block_size),
                }))
                .unwrap();
            return;
        }
        self.push_data_inner(buffer, true);
    }

    fn push_data_inner(&mut self, buffer: &[u8], last: bool) {
        self.block_semaphore.acquire();
        self.sent_length += buffer.len() as u64;
        let block_semaphore = Arc::clone(&self.block_semaphore);
        let data = DataWrapper {
            identifier: self.id.clone(),
            data: Arc::new(SyncUnsafeCell::new(Vec::from(buffer))),
            semaphore: block_semaphore,
            length: buffer.len(),
            last,
            total_data_length: self.length,
            sent_data_length: self.sent_length,
        };

        self.operation_sender
            .send(Operation::Data(Arc::new(data)))
            .expect("Failed to send data.");
    }
}

impl<Tag> Drop for FragmentSender<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    fn drop(&mut self) {
        self.id_semaphore.release()
    }
}
