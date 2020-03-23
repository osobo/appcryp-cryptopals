use code::english2;
use cryptopals::code;

use rayon::prelude::*;

// OBSERVE: slow
fn eval_keysize(inp: &[u8], ksize: usize) -> f32 {
    // number of whole chunks
    let chunks = inp.len() / ksize;
    // Going to calc distance between all pairs of chunks
    // Total number of pairs where order doesn't matter:
    let tot_pairs = (chunks * chunks - chunks) / 2;

    let distance_sum: usize = (0..chunks)
        .into_par_iter()
        .map(|i| {
            rayon::iter::repeat(i)
                .zip((i + 1)..chunks)
        })
        .flatten()
        .map(|(i, j)| {
            let a = i * ksize;
            let b = j * ksize;
            let a = &inp[a..(a + ksize)];
            let b = &inp[b..(b + ksize)];
            code::hamming_distance(a, b)
        })
        .sum();

    let avg_per_chunk = (distance_sum as f32) / (tot_pairs as f32);
    let avg_per_byte = avg_per_chunk / (ksize as f32);
    return avg_per_byte;
}

/// Return (key,plain)
fn crack_with_ksize(inp: &[u8], ksize: usize) -> (Vec<u8>, Vec<u8>) {
    let mut plain = vec![0; inp.len()];
    let mut key = Vec::with_capacity(ksize);
    for chunk_idx in 0..ksize {
        let chunk: Vec<_> =
            inp.iter().copied().skip(chunk_idx).step_by(ksize).collect();
        let (k, _, decr_s) = code::crack_single_xor(english2::scorer, &chunk)
            .expect("No key byte gives valid text");
        (0..inp.len())
            .skip(chunk_idx)
            .step_by(ksize)
            .zip(decr_s.as_bytes())
            .for_each(|(i, x)| plain[i] = *x);
        key.push(k);
    }
    return (key, plain);
}

// cands - (key,avg_dist) pairs sorted, best to worst
// returns best (and shortest) key
fn best_keysize(cands: &[(usize, f32)]) -> usize {
    // If real keysize is eg 100, 200 might have a similar distance
    let (best_len, best_dst) = cands[0];
    let mut factors: Vec<_> = cands
        .iter()
        .copied()
        .filter(|(len, _)| best_len % len == 0)
        .filter(|(_, dst)| (dst - best_dst) < 0.1) // TODO: arbitrary
        .collect();
    factors.sort_by_key(|(len, _)| *len);
    // factors now have all the keylens that divide the best keylength,
    // sorted to it starts with the smallest one

    return factors[0].0;
}

fn find_keysize(inp: &[u8]) -> usize {
    assert!(inp.len() > 2);
    let mut cands: Vec<_> = (1..(inp.len() / 2))
        .map(|ksize| (ksize, eval_keysize(inp, ksize)))
        .collect();
    cands.sort_by(|(_, dst1), (_, dst2)| dst1.partial_cmp(dst2).unwrap());

    return best_keysize(&cands);
}

fn their_ex() -> Vec<u8> {
    let path = "challenge-data/6.txt";
    let inp = code::load_str(path);
    return code::decode_base64(&inp);
}

#[allow(dead_code)]
fn my_ex() -> Vec<u8> {
    let path = "custom-data/eng-ascii1-encr100.hex";
    let inp = code::load_str(path);
    return code::decode_hex(&inp);
}

fn main() {
    let inp = their_ex();
    //let inp = my_ex();
    let ksize = find_keysize(&inp);
    let (key, plain) = crack_with_ksize(&inp, ksize);
    let plain_str = std::str::from_utf8(&plain).unwrap();
    println!("{}\n ---\n{:?}", plain_str, key);
    if let Ok(key_str) = std::str::from_utf8(&key) {
        println!("Key as string: '{}'", key_str);
    }
}
