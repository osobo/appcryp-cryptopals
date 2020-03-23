use cryptopals::code;

use std::io::{Write,stdout};

fn main() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0u8; 16];
    let aes = code::aes128::Aes128::new(key);

    let inp = code::load_str("challenge-data/10.txt");
    let mut buf = code::decode_base64(&inp);

    aes.cbc_decr(&iv, &mut buf);

    stdout().write_all(&buf).unwrap();
}
