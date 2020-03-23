use cryptopals::code;

use code::english2;

fn main() {
    let hexin = concat!(
        "1b37373331363f78151b7f2b783431333d",
        "78397828372d363c78373e783a393b3736"
    );
    let inp = code::decode_hex(hexin);

    let (key, _, decr) =
        code::crack_single_xor(english2::scorer, &inp).expect("No key worked");
    println!("Best key = {} = 0x{:02x}\n{}", key, key, decr);
}
