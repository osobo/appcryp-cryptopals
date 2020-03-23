use cryptopals::code;

use std::iter::repeat;

fn sanitize_userdata(userdata: &str) -> String {
    userdata
        .chars()
        .filter(|c| *c != ';')
        .filter(|c| *c != '=')
        .collect()
}

const PREFIX: &str = "comment1=cooking%20MCs;userdata=";
const SUFFIX: &str = ";comment2=%20like%20a%20pound%20of%20bacon";

/// The first function described.
/// Prepends `PREFIX` and appends `SUFFIX`,
/// then encrypts using the hidden key in CBC with random iv.
/// Returns the used iv and resulting cipher text
fn encrypt(userdata: &str) -> (Vec<u8>, Vec<u8>) {
    let sanitized = sanitize_userdata(userdata).into_bytes().into_iter();
    let mut buf: Vec<_> = PREFIX
        .bytes()
        .chain(sanitized)
        .chain(SUFFIX.bytes())
        .collect();
    let iv = code::rnd(code::aes128::BLOCKSIZE);
    code::blackbox_aes().cbc_encr(&iv, &mut buf);
    return (iv, buf);
}

/// Second function described.
/// Doesn't parse into string.
fn decrypt(iv: &[u8], cipher: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(cipher);
    code::blackbox_aes().cbc_decr(iv, &mut buf);
    return buf;
}

struct Userdata {
    /// The user data to supply the encryption function with
    data: String,
    /// The block index to the block before the block with the admin string
    prevblock: usize,
    /// Set of block-internal byte offsets to the the bytes to
    /// flip the lowest bits of.
    byteoffsets: Vec<u8>,
}

/// Returns (idx,string) where string is the
/// the userdata and idx is the byte index of the
/// byte to flip least sig bit of.
fn construct_userdata() -> Userdata {
    let bs = code::aes128::BLOCKSIZE;

    // Flipping least sig bit of ':' gives ';'
    // Flipping least sig bit of '<' gives '='
    let s = String::from(":admin<true");
    assert!(s.len() < bs && s.len() < (u8::max_value() as usize));
    let idx1 = s.find(":").unwrap() as u8;
    let idx2 = s.find("<").unwrap() as u8;

    // First we pad to fill out the block PREFIX ends in
    let padlen1 = (bs - (PREFIX.len() % bs)) % bs;
    // Then a full block of non-important user data we can scramble
    let padlen2 = bs;
    let data = repeat('a')
        .take(padlen1)
        .chain(repeat('b').take(padlen2))
        .chain(s.chars())
        .collect();
    // Block index to the block before the block with the string we want
    // to manipulate. Ie block index to the block to make the flips in to
    // affect the the string in the desired way.
    let blk = code::ceil_int_div(PREFIX.len(), bs);
    return Userdata {
        data: data,
        prevblock: blk,
        byteoffsets: vec![idx1, idx2],
    };
}

fn main() {
    let bs = code::aes128::BLOCKSIZE;
    let userdata = construct_userdata();
    let (iv, mut cipher) = encrypt(&userdata.data);

    let prevblock = cipher
        .chunks_exact_mut(bs)
        .skip(userdata.prevblock)
        .next()
        .expect("Cipher text could not possibly be this short");
    for i in userdata.byteoffsets {
        prevblock[i as usize] ^= 0x1; // Flip least sig bit
    }

    let decr = decrypt(&iv, &cipher);
    let decr = code::pkcs7_validate(&decr).expect("Bad padding");

    println!("decr = {:?}", decr);
    let decr_str = String::from_utf8_lossy(&decr);
    println!("As text:\n[{}]", decr_str);
}
