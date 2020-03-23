use cryptopals::code;

fn testit(inp: &[u8]) {
    match code::pkcs7_validate(inp) {
        Some(slice) => {
            let vec = Vec::from(slice);
            let s = String::from_utf8(vec).unwrap();
            println!("{}", s);
        }
        None => println!("Not valid"),
    }
}

fn main() {
    let inp1 = b"ICE ICE BABY\x04\x04\x04\x04";
    let inp2 = b"ICE ICE BABY\x05\x05\x05\x05";
    let inp3 = b"ICE ICE BABY\x01\x02\x03\x04";

    testit(inp1);
    testit(inp2);
    testit(inp3);
}
