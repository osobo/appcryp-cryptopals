
use cryptopals::code;

use std::iter::once;

static STRS: &[&str] = &[
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
];

fn random_inp() -> Vec<u8> {
    let i = code::rnd_interval(0, STRS.len()-1);
    let b64 = STRS[i];
    let bytes = code::decode_base64(b64);
    let s = String::from_utf8(bytes.clone()).unwrap();
    println!("Using random input\n{} =\n{}\n", b64, s);
    return bytes;
}

// Assuming we should generate random iv

/// Encrypts a random string with an unknown key
/// Uses random IV
/// Returns (iv,cipher)
fn random_cbc() -> (Vec<u8>, Vec<u8>) {
    let iv = code::rnd(code::aes128::BLOCKSIZE);
    let plain = random_inp();
    let mut buf = Vec::from(plain);
    code::blackbox_aes().cbc_encr(&iv, &mut buf);
    return (iv, buf);
}

fn check_cbc_padding(iv: &[u8], cipher: &[u8]) -> bool {
    let mut buf = Vec::from(cipher);
    code::blackbox_aes().cbc_decr(iv, &mut buf);
    return code::pkcs7_validate(&buf).is_some();
}

fn crack_block(prev: &[u8], this: &[u8]) -> Vec<u8> {
    let mut buf = decrypt_block(this);
    code::block_xor(&mut buf, prev);
    return buf;
}

fn crack_cbc(iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let blocksize = code::aes128::BLOCKSIZE;
    let cipherblocks = ciphertext.chunks_exact(blocksize);
    let with_iv = once(iv).chain(ciphertext.chunks_exact(blocksize));
    let mut buf = Vec::with_capacity(ciphertext.len());
    with_iv.zip(cipherblocks)
        .map(|(prev,this)| crack_block(prev, this))
        .for_each(|v| buf.extend(v));
    return buf;
}

/// Cracks what AES_DECRYPT(KEY, `cipherblock`) is.
/// So does _not_ return final plaintext since
/// it is not XOR:ed with previous ciphertext.
fn decrypt_block(cipherblock: &[u8]) -> Vec<u8> {
    let blocksize = cipherblock.len();
    let mut decrblock = vec![0; blocksize];
    let mut ivp = vec![0;blocksize];

    // Special case for cracking last byte.
    // If you get valid padding, that's _probably_ because
    // last byte is 0x01 is decrypted block. But could also be eg 0x02, 0x02.
    for b in 0..=255 {
        ivp[blocksize - 1] = b;
        if check_cbc_padding(&ivp, cipherblock) {
            // This is _not_ certainly a hit
            // Say last byte of decrypted block is x
            // All we know is that 1 <= x <= blocksize
            // and that the last x bytes in decrypted block are all x.
            // If x > 1, then second to last byte must also be x.
            // If that byte was xor:ed with anything other than what is in
            // ivp at that position now, would no longer be valid padding.
            // BUT, if x=1, then chaning second last byte won't change
            // padding to not valid.
            ivp[blocksize-2] ^= 1; // Flip a bit to make it different
            if check_cbc_padding(&ivp, cipherblock) {
                // Ok, now we can be certain that last byte is 0x01
                decrblock[blocksize-1] = b ^ 0x01;
            } else {
                // b is not a hit, don't need to do anything here
                eprintln!("\n== Skipping b=0x{:02x} on first byte ==\n", b);
            }
        }
    }

    // Crack byte i, starting at the second to last byte of the block
    // No need to double check here since we force what the last byte
    // of decrypted block is.
    for i in (0..(blocksize-1)).rev() {
        let padbyte = (blocksize-i) as u8;
        // First we need to set ivp[i+1], ..., ivp[blocksize-1]
        for j in (i+1)..blocksize {
            ivp[j] = decrblock[j] ^ padbyte;
        }

        // Then cycle over ivp[i] until correct padding
        for b in 0..=255 {
            ivp[i] = b;
            if check_cbc_padding(&ivp, cipherblock) {
                // We know that last of decr is padbyte
                // Valid padding -> last padbyte blocks all equal padbyte
                // Since padbyte=blocksize-i, decr[i] = padbyte
                // CBC -> decrblock[i] ^ b = padbyte ->
                // decrblock[i] = b ^ padbyte
                decrblock[i] = b ^ padbyte;
            }
        }
    }
    assert!(decrblock.len() == blocksize);
    return decrblock;
}

fn main() {
    let (iv, cipher) = random_cbc();
    
    let plain = crack_cbc(&iv, &cipher);
    println!("Plain before unpad:\n{:02x?}", plain);
    let plain = code::pkcs7_validate(&plain).expect("Bad padding?");
    let s = String::from_utf8(Vec::from(plain)).unwrap();
    println!("After removing padding\n{:02x?}\nstring = [{}]", plain , s);
}
