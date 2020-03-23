use cryptopals::code;

use rand;

// Generates between 5 and 10 random bytes
fn some_rnd() -> Vec<u8> {
    let count = code::rnd_interval(5, 10);
    code::rnd(count)
}

fn rnd_encr(inp: &[u8]) -> Vec<u8> {
    let key = code::rnd(16);
    let aes = code::aes128::Aes128::new(&key);

    let pre = some_rnd();
    let post = some_rnd();
    let mut buf: Vec<_> = pre.iter()
        .chain(inp.iter())
        .chain(post.iter())
        .copied()
        .collect();

    if rand::random() {
        // 50% chance of ecb
        println!("Encrypting with ECB");
        aes.ecb_encr(&mut buf);
    } else {
        // 50% change of cbc
        println!("Encrypting with CBC");
        let iv = code::rnd(16);
        aes.cbc_encr(&iv, &mut buf);
    }

    return buf;
}

fn main() {
    let plain = [0u8; 4*16];
    let cipher = rnd_encr(&plain);
    // Second and third block plain text will be all 0, regardless
    // of randomness. So in ecb they will be same in ciphertext
    let second = &cipher[16..32];
    let third = &cipher[32..48];
    let ecb = second.iter()
        .zip(third.iter())
        .map(|(s,t)| s == t)
        .all(|b| b);

    if ecb {
        println!("Guess ECB");
    } else {
        println!("Guess CBC");
    }
}
