use parking_lot::{Condvar, Mutex};

#[derive(Debug)]
pub struct SimpleSemaphore {
    counter: Mutex<usize>,
    condvar: Condvar,
    max_count: usize,
}

impl SimpleSemaphore {
    pub fn new(size: usize) -> Self {
        Self {
            counter: Mutex::new(0),
            condvar: Condvar::new(),
            max_count: size,
        }
    }

    pub fn acquire(&self) {
        let mut count = self.counter.lock();

        while *count >= self.max_count {
            self.condvar.wait(&mut count);
        }

        *count += 1;
    }

    pub fn release(&self) {
        let mut count = self.counter.lock();

        if *count == 0 {
            return;
        }

        *count -= 1;

        self.condvar.notify_one();
    }
}
