use cryptopals::code;

use code::english2;

fn main() {
    let path = "challenge-data/4.txt";
    let inp = code::load_str(path);

    let mut decrs: Vec<_> = inp
        .lines()
        .filter_map(|l| {
            let bytes = code::decode_hex(l);
            code::crack_single_xor(english2::scorer, &bytes)
                .map(|(k,score,decr_s)| (k,score,l,decr_s))
        })
        .collect();
    decrs.sort_by_key(|(_, score, _, _)| *score);

    println!(concat!(
        "Here are all the lines that could be decrypted",
        "to utf-8, best to worst\n"
    ));

    for (k, _, l, decr_str) in decrs {
        println!("key 0x{:02x} on {} ->\n[{}]\n", k, l, decr_str);
    }
}
