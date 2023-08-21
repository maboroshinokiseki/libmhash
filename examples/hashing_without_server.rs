use libmhash::paranoid_hash::{Hasher, SHA1};

fn main() {
    let mut sha1 = SHA1::new();

    let mut download_buffer = [0u8; SHA1::BLOCK_SIZE * 2];
    for i in 0..128u8 {
        // protend to download data from the internet
        download_buffer.fill(i);

        // buffer length must be a multiple of hasher block size
        sha1.update(&download_buffer).unwrap();
    }

    // buffer length must be less or equal to hasher block size
    sha1.update_last(&[]).unwrap();

    // you can only call digest after update_last, even if the last piece of data is empty
    println!("{:02x?}", sha1.digest().unwrap());
}
