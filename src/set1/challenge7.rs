use cryptopals::code;

fn main() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let cipher_b64 = code::load_str("challenge-data/7.txt");
    let mut buf = code::decode_base64(&cipher_b64);

    let aes = code::aes128::Aes128::new(&key);
    aes.ecb_decr(&mut buf);

    let plain = std::str::from_utf8(&buf).unwrap();
    println!("{}", plain);
}
