use std::{fs::OpenOptions, hash::Hash, io::Read, path::Path, sync::Arc};

use crossbeam_channel::Sender;
use threadpool::ThreadPool;

use crate::{
    hasher_server::{
        data_wrapper::DataWrapper, fragment_sender::FragmentSender, hasher_wrapper::HasherWrapper,
        operation::Operation, sync_unsafe_cell::SyncUnsafeCell, HasherError, Identifier,
    },
    simple_semaphore::SimpleSemaphore,
};

#[derive(Debug)]
pub struct DataSender<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub(super) block_size: usize,
    pub(super) block_count: usize,
    pub(super) operation_sender: Sender<Operation<Tag>>,
    pub(super) id_semaphore: Arc<SimpleSemaphore>,
    pub(super) reader_threads: ThreadPool,
}

impl<Tag> DataSender<Tag>
where
    Tag: Clone + Eq + Hash + Send + 'static,
{
    pub fn push_file(&self, filename: impl AsRef<Path>, hashers: Vec<HasherWrapper<Tag>>) {
        if hashers.is_empty() {
            return;
        }

        let identifier: Identifier = filename.as_ref().into();

        let operation_sender = self.operation_sender.clone();

        let mut file = unwrap_or_return!(
            OpenOptions::new().read(true).open(&filename),
            identifier,
            None,
            operation_sender
        );

        let file_size =
            unwrap_or_return!(file.metadata(), identifier, None, operation_sender).len();

        operation_sender
            .send(Operation::NewIdentifier {
                identifier: identifier.clone(),
                hashers,
            })
            .expect("Failed to send new identifier.");

        let block_count = self.block_count;
        let block_size = self.block_size;

        let id_semaphore = Arc::clone(&self.id_semaphore);
        id_semaphore.acquire();

        self.reader_threads.execute(move || {
            let block_semaphore = Arc::new(SimpleSemaphore::new(block_count));

            let mut buffers = Vec::with_capacity(block_count);
            for _ in 0..block_count {
                buffers.push(Arc::new(SyncUnsafeCell::new(vec![0u8; block_size])));
            }

            let mut sent_file_size = 0;
            let mut buffer_index = 0;

            loop {
                block_semaphore.acquire();

                // Reading data
                let size_to_read = u64::min(file_size - sent_file_size, block_size as u64);
                sent_file_size += size_to_read;

                let buffer = &buffers[buffer_index];
                buffer_index = (buffer_index + 1) % block_count;

                unwrap_or_break!(
                    file.read_exact(&mut buffer.get_mut()[..size_to_read as usize]),
                    identifier,
                    None,
                    operation_sender
                );

                // Sending data
                let block_semaphore = Arc::clone(&block_semaphore);
                let data = DataWrapper {
                    identifier: identifier.clone(),
                    data: Arc::clone(buffer),
                    semaphore: block_semaphore,
                    length: size_to_read as usize,
                    last: file_size == sent_file_size,
                    total_data_length: file_size,
                    sent_data_length: sent_file_size,
                };

                operation_sender
                    .send(Operation::Data(Arc::new(data)))
                    .expect("Failed to send data.");

                if sent_file_size == file_size {
                    break;
                }
            }

            id_semaphore.release();
        })
    }

    pub fn fragment_sender(
        &mut self,
        name: impl Into<Identifier>,
        hashers: Vec<HasherWrapper<Tag>>,
    ) -> FragmentSender<Tag> {
        self.id_semaphore.acquire();
        let id = name.into();
        self.operation_sender
            .send(Operation::NewIdentifier {
                identifier: id.clone(),
                hashers,
            })
            .expect("Failed to send new identifier.");

        FragmentSender {
            id,
            length: 0,
            sent_length: 0,
            block_size: self.block_size,
            operation_sender: self.operation_sender.clone(),
            id_semaphore: self.id_semaphore.clone(),
            block_semaphore: Arc::new(SimpleSemaphore::new(self.block_count)),
        }
    }

    pub fn end(&self) {
        self.operation_sender
            .send(Operation::EndOfNewIdentifier)
            .unwrap()
    }
}
