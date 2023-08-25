use std::{collections::HashMap, hash::Hash, thread};

enum Operation<K>
where
    K: Eq + Hash + Send + Clone + 'static,
{
    Add(Job<K>),
    Done(K),
    DoneBy(Box<dyn Fn(&K) -> bool + Send + 'static>),
}

enum ExecutorOperation {
    Job(Box<dyn FnOnce() + Send>),
    Done,
}

struct Job<K>
where
    K: Eq + Hash + Send + Clone + 'static,
{
    pub tag: K,
    pub job: Box<dyn FnOnce() + Send>,
}

impl<K> Job<K>
where
    K: Eq + Hash + Send + Clone + 'static,
{
    fn new(tag: K, job: Box<dyn FnOnce() + Send>) -> Self {
        Self { tag, job }
    }
}

pub struct TagThreadPool<K>
where
    K: Eq + Hash + Send + Clone + 'static,
{
    dispatcher: crossbeam_channel::Sender<Operation<K>>,
}

impl<K> TagThreadPool<K>
where
    K: Eq + Hash + Send + Clone + 'static,
{
    pub fn new() -> Self {
        let (dispatcher, receiver) = crossbeam_channel::unbounded::<Operation<K>>();
        let thread_pool = threadpool::Builder::new().build();
        let dispatcher_for_finish = dispatcher.clone();
        thread::spawn(move || {
            let mut job_senders = HashMap::new();

            loop {
                let operation = match receiver.recv() {
                    Ok(operation) => operation,
                    Err(_) => break,
                };

                let _ = match operation {
                    Operation::Add(job) => job_senders
                        .entry(job.tag.clone())
                        .or_insert_with(|| {
                            let (sender, receiver) =
                                crossbeam_channel::unbounded::<ExecutorOperation>();

                            thread_pool.execute(move || loop {
                                if let Ok(operation) = receiver.recv() {
                                    match operation {
                                        ExecutorOperation::Job(job) => (job)(),
                                        ExecutorOperation::Done => break,
                                    }
                                }
                            });

                            sender
                        })
                        .send(ExecutorOperation::Job(job.job)),
                    Operation::Done(tag) => match job_senders.remove(&tag) {
                        Some(sender) => sender.send(ExecutorOperation::Done),
                        None => Ok(()),
                    },
                    Operation::DoneBy(filter) => {
                        for key in job_senders.keys().filter(|k| (filter)(k)) {
                            let _ = dispatcher_for_finish.send(Operation::Done(key.clone()));
                        }
                        Ok(())
                    }
                };
            }
        });

        TagThreadPool { dispatcher }
    }

    pub fn dispatch<F>(&self, tag: K, job: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.dispatcher
            .send(Operation::Add(Job::new(tag, Box::new(job))))
            .unwrap();
    }

    pub fn finish(&self, tag: K) {
        self.dispatcher.send(Operation::Done(tag)).unwrap();
    }

    pub fn finish_by<F>(&self, filter: F)
    where
        F: Fn(&K) -> bool + Send + 'static,
    {
        self.dispatcher
            .send(Operation::DoneBy(Box::new(filter)))
            .unwrap();
    }
}
