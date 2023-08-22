use std::{collections::HashMap, hash::Hash, thread, time::Duration};

enum Operation<K>
where
    K: Eq + Hash + Send + Clone + 'static,
{
    Add(Job<K>),
    Done(K),
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
        let tx = dispatcher.clone();
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

                            let tag = job.tag.clone();
                            let tx = tx.clone();
                            thread_pool.execute(move || loop {
                                match receiver.recv_timeout(Duration::from_millis(128)) {
                                    Ok(operation) => match operation {
                                        ExecutorOperation::Job(job) => (job)(),
                                        ExecutorOperation::Done => break,
                                    },
                                    Err(_) => tx.send(Operation::Done(tag.clone())).unwrap(),
                                }
                            });

                            sender
                        })
                        .send(ExecutorOperation::Job(job.job)),
                    Operation::Done(tag) => job_senders
                        .remove(&tag)
                        .unwrap()
                        .send(ExecutorOperation::Done),
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
}
