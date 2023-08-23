use libmhash::prelude::*;

fn main() {
    // create a hasher server
    let mut server = Builder::new()
        .on_result(Some(|r: &HasherResult<HasherTag>| println!("{:#?}", r)))
        .build()
        .unwrap();

    // use sender to send files or raw data
    let mut sender = server.data_sender();

    // you can also send files without spawning a new thread
    std::thread::spawn(move || {
        // create hashers
        let mut hashers = vec![];

        // tags can be String or something else, but better choose something cheap to clone.
        hashers.push(HasherWrapper::new(
            HasherTag::SHA1,
            libmhash::paranoid_hash::SHA1::new(),
        ));

        // you can also create HasherWrapper from HasherTags
        hashers.push(HasherWrapper::create_from_tag(HasherTag::MD5));

        let mut fragment_sender = sender.fragment_sender("Temp Data", hashers);

        let mut download_buffer = [0u8; 128];
        for i in 0..128u8 {
            // protend to download data from the internet
            download_buffer.fill(i);

            // buffer length must be a multiple of server block size
            fragment_sender.push_data(&download_buffer);
        }

        // buffer length must be less or equal to server block size
        fragment_sender.push_last_data(&[]);

        // don't forget to call end, otherwise the hasher server will keep waiting for new data.
        sender.end();
    });

    // do the computations, callbacks will be called in the same thread.
    server.compute();
}
