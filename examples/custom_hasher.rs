use std::sync::Arc;

use libmhash::{paranoid_hash::Hasher, prelude::*, Result};

// a very simple hasher
struct MyHasher {
    state: u8,
}

impl Hasher for MyHasher {
    fn update(&mut self, data: &[u8]) -> Result<()> {
        for d in data {
            self.state ^= *d
        }

        Ok(())
    }

    fn update_last(&mut self, data: &[u8]) -> Result<()> {
        self.update(data)
    }

    fn digest(&self) -> Result<&[u8]> {
        Ok(std::slice::from_ref(&self.state))
    }

    fn reset(&mut self) {
        self.state = 0;
    }

    fn block_size(&self) -> usize {
        1
    }

    fn digest_size(&self) -> usize {
        1
    }
}

fn main() {
    // create a hasher server
    let mut server = Builder::new()
        .on_result(Some(|r: &HasherResult<Arc<&str>>| println!("{:#?}", r)))
        .build()
        .unwrap();

    // use sender to send file or raw data
    let sender = server.data_sender();

    // you can also send files without spawning a new thread
    std::thread::spawn(move || {
        for entry in std::fs::read_dir(".").unwrap() {
            let dir = entry.unwrap();
            if dir.path().is_file() {
                // create hashers
                let mut hashers = vec![];

                // tags can be String or something else, but better choose something cheap to clone.
                hashers.push(HasherWrapper::new(
                    Arc::new("My Hasher"),
                    MyHasher { state: 0 },
                ));

                // send files
                sender.push_file(dir.path(), hashers);
            }
        }

        // don't forget to call end, otherwise the hasher server will keep waiting for new data.
        sender.end();
    });

    // do the computations, callbacks will be called in the same thread.
    server.compute();
}
