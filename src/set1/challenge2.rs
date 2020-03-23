use cryptopals::code;

fn main() {
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";
    println!("{}\n{}", a, b);
    let a = code::decode_hex(a);
    let mut b = code::decode_hex(b);
    code::block_xor(&mut b, &a);
    let hex = code::encode_hex(&b);
    println!("{}", hex);
}
