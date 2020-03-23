use cryptopals::code;

fn main() {
    let inp = "YELLOW SUBMARINE";
    let mut buf = Vec::from(inp.as_bytes());
    code::pkcs7_pad(&mut buf, 5);
    let inp = code::encode_hex(inp.as_bytes());
    let out = code::encode_hex(&buf);
    println!("{}\n{}", inp, out);
}
