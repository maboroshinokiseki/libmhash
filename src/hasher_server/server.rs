use std::{collections::HashMap, hash::Hash, sync::Arc};

use crate::{
    hasher_server::{operation::Operation, *},
    simple_semaphore::SimpleSemaphore,
    tag_thread_pool::TagThreadPool,
    Error,
};

use crossbeam_channel::{Receiver, Sender};

#[derive(Debug)]
pub struct HasherServer<Tag, P, R, E>
where
    Tag: Clone + Eq + Hash + Send,
{
    pub(super) operation_channel: (Sender<Operation<Tag>>, Receiver<Operation<Tag>>),
    pub(super) block_size: usize,
    pub(super) block_count: usize,
    pub(super) id_count: usize,
    pub(super) id_semaphore: Arc<SimpleSemaphore>,
    pub(super) progress_callback: Option<P>,
    pub(super) result_callback: Option<R>,
    pub(super) error_callback: Option<E>,
}

impl<Tag, P, R, E> HasherServer<Tag, P, R, E>
where
    Tag: Clone + Eq + Hash + Send,
{
    fn do_hashing(
        &self,
        hasher_map: &mut HashMap<Identifier, Vec<HasherWrapper<Tag>>>,
        data_wrapper: Arc<DataWrapper>,
        hasher_threads: &TagThreadPool<IdentifierHasherTag<Tag>>,
    ) {
        let Some(hashers) = hasher_map.get(&data_wrapper.identifier) else {
                return;
        };

        for hasher_wrapper in hashers {
            let hasher_wrapper = hasher_wrapper.shallow_clone();
            let data_wrapper = Arc::clone(&data_wrapper);
            let tag = IdentifierHasherTag {
                identifier: data_wrapper.identifier.clone(),
                tag: hasher_wrapper.tag.clone(),
            };
            let operation_sender = self.operation_channel.0.clone();
            hasher_threads.dispatch(tag, move || {
                let buffer: &Vec<u8> = data_wrapper.data.get_mut();
                let hasher_tag = hasher_wrapper.tag.clone();
                let hasher_inner = hasher_wrapper.hasher.get_mut();
                let buffer = &buffer[..data_wrapper.length];
                if !data_wrapper.last {
                    unwrap_or_return!(
                        hasher_inner.update(buffer),
                        data_wrapper.identifier.clone(),
                        Some(hasher_tag),
                        operation_sender
                    );

                    operation_sender
                        .send(Operation::Progress(HasherProgress {
                            identifier: data_wrapper.identifier.clone(),
                            tag: hasher_tag,
                            total_data_length: data_wrapper.total_data_length,
                            processed_data_length: data_wrapper.sent_data_length,
                        }))
                        .unwrap();
                } else {
                    let seperator =
                        data_wrapper.length / hasher_inner.block_size() * hasher_inner.block_size();

                    unwrap_or_return!(
                        hasher_inner.update(&buffer[..seperator]),
                        data_wrapper.identifier.clone(),
                        Some(hasher_tag),
                        operation_sender
                    );

                    unwrap_or_return!(
                        hasher_inner.update_last(&buffer[seperator..]),
                        data_wrapper.identifier.clone(),
                        Some(hasher_tag),
                        operation_sender
                    );

                    operation_sender
                        .send(Operation::Result(HasherResultPrivate {
                            identifier: data_wrapper.identifier.clone(),
                            hasher_wrapper,
                        }))
                        .unwrap();
                }
            });
        }
    }

    fn delete_hasher(
        hasher_map: &mut HashMap<Identifier, Vec<HasherWrapper<Tag>>>,
        identifier: &Identifier,
        tag: &Tag,
    ) {
        let Some(hashers) = hasher_map.get_mut(identifier) else {
            return;
        };
        let Some(index) = hashers.iter().position(|h| h.tag == *tag) else {
            return;
        };
        hashers.swap_remove(index);
        if hashers.is_empty() {
            hasher_map.remove(identifier);
        }
    }
}

pub trait HasherServerTrait {
    type Tag: Clone + Eq + Hash + Send;

    fn data_sender(&self) -> DataSender<Self::Tag>;

    fn compute(&mut self);

    fn block_size(&self) -> usize;
}

impl<Tag, P, R, E> HasherServerTrait for HasherServer<Tag, P, R, E>
where
    Tag: Clone + Eq + Hash + Send + 'static,
    P: FnMut(&HasherProgress<Tag>),
    R: FnMut(&HasherResult<Tag>),
    E: FnMut(&HasherError<Tag>),
{
    type Tag = Tag;

    fn data_sender(&self) -> DataSender<Tag> {
        DataSender {
            block_size: self.block_size,
            block_count: self.block_count,
            operation_sender: self.operation_channel.0.clone(),
            id_semaphore: Arc::clone(&self.id_semaphore),
            reader_threads: threadpool::Builder::new()
                .num_threads(self.id_count)
                .build(),
        }
    }

    fn compute(&mut self) {
        let mut hasher_map = HashMap::new();
        let mut end_of_list = false;

        let operation_sender = self.operation_channel.0.clone();

        let hasher_threads = TagThreadPool::<IdentifierHasherTag<Tag>>::new();

        loop {
            if end_of_list && hasher_map.is_empty() {
                break;
            }

            let operation = match self.operation_channel.1.recv() {
                Ok(operation) => operation,
                Err(error) => {
                    eprintln!("channel error: {error}");
                    break;
                }
            };

            match operation {
                Operation::NewIdentifier {
                    identifier,
                    hashers,
                } => {
                    if end_of_list {
                        operation_sender
                            .send(Operation::Error(HasherError {
                                identifier,
                                tag: None,
                                error: Error::DataEnded,
                            }))
                            .unwrap();
                        continue;
                    }

                    hasher_map.insert(identifier, hashers);
                }
                Operation::EndOfNewIdentifier => end_of_list = true,
                Operation::Data(data_wrapper) => {
                    self.do_hashing(&mut hasher_map, data_wrapper, &hasher_threads)
                }
                Operation::Progress(progress) => {
                    if let Some(callback) = self.progress_callback.as_mut() {
                        (callback)(&progress)
                    }
                }
                Operation::Result(result) => {
                    let hasher = result.hasher_wrapper.hasher.get_mut();
                    let pub_result = HasherResult {
                        identifier: result.identifier.clone(),
                        tag: result.hasher_wrapper.tag.clone(),
                        hasher,
                    };
                    if let Some(callback) = self.result_callback.as_mut() {
                        (callback)(&pub_result)
                    }

                    Self::delete_hasher(
                        &mut hasher_map,
                        &result.identifier,
                        &result.hasher_wrapper.tag,
                    );

                    let tag = IdentifierHasherTag {
                        identifier: result.identifier,
                        tag: result.hasher_wrapper.tag,
                    };
                    hasher_threads.finish(tag);
                }
                Operation::Error(error) => {
                    if let Some(callback) = self.error_callback.as_mut() {
                        (callback)(&error)
                    }

                    match error.tag {
                        Some(tag) => {
                            Self::delete_hasher(&mut hasher_map, &error.identifier, &tag);

                            let tag = IdentifierHasherTag {
                                identifier: error.identifier.clone(),
                                tag,
                            };
                            hasher_threads.finish(tag);
                        }
                        None => {
                            hasher_map.remove(&error.identifier);

                            hasher_threads.finish_by(move |k| k.identifier == error.identifier);
                        }
                    }
                }
            }
        }
    }

    fn block_size(&self) -> usize {
        self.block_size
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
struct IdentifierHasherTag<Tag>
where
    Tag: Clone + Eq + Hash + Send,
{
    identifier: Identifier,
    tag: Tag,
}
