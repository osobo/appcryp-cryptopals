use cryptopals::code;

fn main() {
    let plain = "custom-data/eng-ascii1.txt";
    let key = "custom-data/rnd-bin-key-100";

    let plain = code::load_file(plain);
    let key = code::load_file(key);

    let cipher = code::repeat_xor(&plain, &key);
    let cipher = code::encode_hex(&cipher);

    println!("{}", cipher);
}
