use cryptopals::code;

use std::iter::{once, repeat};

fn ctr_fixed(inp: &mut [u8]) {
    let nonce = 0u64;
    code::blackbox_aes().ctr_inplace(nonce, inp);
}

fn ciphertexts() -> Vec<Vec<u8>> {
    let f = code::load_str("challenge-data/19.txt");
    f.lines()
        .map(|b64| code::decode_base64(b64))
        .map(|mut buf| {
            ctr_fixed(&mut buf);
            buf
        })
        .collect()
}

/// If normal printable ascii, return ascii char.
/// Else . (like xxd)
fn pretty_char(b: u8) -> char {
    if b >= 0x20 && b <= 0x7e {
        b.into()
    } else {
        '.'
    }
}

/// Show what decrypted part looks like in ascii, followed by remaining
/// in hex
fn showline(keystream: &[u8], cipher: &[u8]) {
    cipher
        .iter()
        .zip(keystream)
        .map(|(x, k)| pretty_char(*k ^ *x))
        .for_each(|c| print!("{}", c));
    println!("");
}

fn show_cursor(j: usize) {
    let s: String = repeat(' ').take(j + 4).chain(once('^')).collect();
    println!("{}", s);
}

fn parse_set_inp(s: &str) -> Option<(usize, u8)> {
    let words: Vec<_> = s.split(' ').collect();
    let nstr = words.get(0)?;
    let cstr = words.get(1)?;

    let n = nstr.parse().ok()?;
    let c = *cstr.as_bytes().get(0)?;

    return Some((n, c));
}

#[derive(Debug)]
enum Command {
    Cycle,
    CycleBack,
    Set(usize, u8),
    Left,
    Right,
}

impl Command {
    fn next() -> Self {
        let mut buf = String::new();
        loop {
            buf.clear();
            std::io::stdin().read_line(&mut buf).unwrap();
            let s = buf.trim();
            if s.len() == 0 {
                return Self::Cycle;
            } else if s == "b" {
                return Self::CycleBack;
            } else if s == "l" {
                return Self::Left;
            } else if s == "r" {
                return Self::Right;
            }

            // Check for set
            if s.len() > 1 {
                let (beg, end) = s.split_at(1);
                if beg == "s" {
                    if let Some((i, c)) = parse_set_inp(end.trim()) {
                        return Self::Set(i, c);
                    }
                }
            }
        }
    }
}

fn show(keystream: &[u8], j: usize, ciphers: &[Vec<u8>]) {
    println!("\n");
    for (i, c) in ciphers.iter().enumerate() {
        print!("{:03} ", i);
        showline(&keystream, &c);
    }
    show_cursor(j);
}

fn session(ciphers: Vec<Vec<u8>>) {
    let maxlen = ciphers.iter().map(|c| c.len()).max().unwrap();
    let mut keystream = vec![0u8; maxlen];
    let mut j = 0;

    loop {
        show(&keystream, j, &ciphers);
        match Command::next() {
            Command::Cycle => keystream[j] = keystream[j].wrapping_add(1),
            Command::CycleBack => keystream[j] = keystream[j].wrapping_sub(1),
            Command::Left => {
                if j > 0 {
                    j -= 1
                }
            }
            Command::Right => {
                if j < maxlen - 1 {
                    j += 1
                }
            }
            Command::Set(i, c) => keystream[j] = c ^ ciphers[i][j]
        };
    }
}

fn main() {
    let ciphers = ciphertexts();
    session(ciphers);
}
