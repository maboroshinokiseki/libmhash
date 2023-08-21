# Description
A file hashing library that can do multiple hashes for multile files at the same time.

# Supported hashes
CRC32, CRC32C, MD2, MD4, MD5, SHA1, SHA2, SHA3

# Example
```rust
use libmhash::prelude::*;

fn main() {
    // create a hasher server
    let mut server = Builder::new()
        .on_result(Some(|r: &HasherResult<HasherTag>| println!("{:#?}", r)))
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
                    HasherTag::SHA1,
                    libmhash::paranoid_hash::SHA1::new(),
                ));

                // // you can also create HasherWrapper from HasherTags
                hashers.push(HasherWrapper::create_from_tag(HasherTag::MD5));

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
```
