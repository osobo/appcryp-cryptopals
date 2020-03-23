use cryptopals::code;

use rayon::prelude::*;

fn ctr_fixed(inp: &mut [u8]) {
    let nonce = 0u64;
    code::blackbox_aes().ctr_inplace(nonce, inp);
}

fn ciphertexts() -> Vec<Vec<u8>> {
    let f = code::load_str("challenge-data/20.txt");
    f.lines()
        .map(|b64| code::decode_base64(b64))
        .map(|mut buf| {
            ctr_fixed(&mut buf);
            buf
        })
        .collect()
}

/// Gets real keystream to compare against
fn get_real_keystream(len: usize) -> Vec<u8> {
    // Encrypt all 0s -> get keystream
    let mut buf = vec![0; len];
    ctr_fixed(&mut buf);
    return buf;
}

/// All ciphers must be same length and encrypted with same keystream
/// Returns keystream and all decrypted strings
fn crack_keystream(ciphers: &[&[u8]]) -> Vec<u8> {
    assert!(ciphers.len() > 1);
    let len = ciphers[0].len();

    (0..len)
        .into_par_iter()
        .map(|i| {
            let bytes: Vec<u8> =
                ciphers.iter().map(|cipher| cipher[i]).collect();
            //let scorer = code::english4::cheaty::scorer;
            let scorer = code::english5::scorer;
            let (k, _, s) = code::crack_single_xor(scorer, &bytes)
                .expect("No keybyte made it into english");
            println!("{:03} -> 0x{:02x},  [{}]", i, k, s);
            k
        })
        .collect()
}

fn main() {
    let ciphers = ciphertexts();

    // Truncate all to smallest length
    let minlen = ciphers.iter().map(|c| c.len()).min().expect("No ciphers?");
    let ciphers: Vec<_> = ciphers.iter().map(|c| &c[0..minlen]).collect();

    let real_keystream = get_real_keystream(minlen);
    let keystream = crack_keystream(&ciphers);

    println!("\n\n");

    println!("Real keystream =\n{:02x?}", real_keystream);
    println!("Cracked keystream =\n{:02x?}", keystream);
    if code::cmp_blocks(&keystream, &real_keystream) {
        println!("They're the same!");
    } else {
        println!("<< MISMATCH! >>");
    }
    println!("\n\n");

    println!("Decrypted strings:");
    for cipher in ciphers {
        let mut buf = Vec::from(cipher);
        code::block_xor(&mut buf, &keystream);
        let s = String::from_utf8(buf)
            .expect("Somehow not string after decryption");
        println!("[{}]", s);
    }
}
