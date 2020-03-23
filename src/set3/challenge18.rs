
use cryptopals::code;

fn main() {
    let nonce = 0u64;

    let key = "YELLOW SUBMARINE";
    let key = key.as_bytes();

    let cipher = concat!(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/",
        "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    );

    let mut buf = code::decode_base64(cipher);

    let aes = code::aes128::Aes128::new(key);
    aes.ctr_inplace(nonce, &mut buf);

    let s = String::from_utf8(buf).unwrap();
    println!("{}", s);
}
