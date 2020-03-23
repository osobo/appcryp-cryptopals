mod manual {
    const TABLE: [char;64] = [
        'A','B','C','D','E','F','G','H',
        'I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X',
        'Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n',
        'o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3',
        '4','5','6','7','8','9','+','/'
    ];

    const PADDING: char = '=';

    const MASK: usize = 1 + 2 + 4 + 8 + 16 + 32;

    fn three2b64(bs: [u8;3]) -> [char;4] {
        let a = (bs[0] >> 2) as usize;
        let b = ((bs[0] << 4) | (bs[1] >> 4)) as usize;
        let c = ((bs[1] << 2) | (bs[2] >> 6)) as usize;
        let d = (bs[2]) as usize;

        let (a,b,c,d) = (a & MASK,
                         b & MASK,
                         c & MASK,
                         d & MASK);

        [TABLE[a], TABLE[b], TABLE[c], TABLE[d]]
    }

    fn two2b64(bs: [u8;2]) -> [char;4] {
        let a = (bs[0] >> 2) as usize;
        let b = ((bs[0] << 4) | (bs[1] >> 4)) as usize;
        let c = (bs[1] << 2) as usize;

        let (a,b,c) = (a & MASK,
                       b & MASK,
                       c & MASK);

        [TABLE[a], TABLE[b], TABLE[c], PADDING]
    }

    fn one2b64(byte: u8) -> [char;4] {
        let a = (byte >> 2) as usize;
        let b = (byte << 4) as usize;

        let (a,b) = (a & MASK,
                     b & MASK);

        [TABLE[a], TABLE[b], PADDING, PADDING]
    }

    fn hex2nibble(h: u8) -> u8 {
        if h >= 65 && h <= 90 {
            h - 65 + 10
        } else if h >= 97 && h <= 122 {
            h - 97 + 10
        } else if h >= 48 && h <= 57 {
            h - 48
        } else {
            panic!("Bad hex");
        }
    }

    fn hex2byte(hi: u8, lo: u8) -> u8 {
        16*hex2nibble(hi) + hex2nibble(lo)
    }

    fn hex2bytes(hex: &str) -> Vec<u8> {
        let hex: &[u8] = hex.as_ref();
        hex.iter().step_by(2).zip(hex.iter().skip(1).step_by(2))
            .map(|(a,b)| hex2byte(*a, *b)).collect()
    }

    fn add4(s: String, [a,b,c,d]: [char;4]) -> String {
        s + &a.to_string()
          + &b.to_string()
          + &c.to_string()
          + &d.to_string()
    }

    #[allow(dead_code)]
    pub fn hex2base64(hex: &str) -> String {
        assert!(hex.len() % 2 == 0);
        let bytes = hex2bytes(hex);
        let last_chunk = bytes.len() % 3;
        let first_chunks = bytes.len() - last_chunk;
        let s = (0..first_chunks).step_by(3)
            .map(|i| three2b64([bytes[i],bytes[i+1],bytes[i+2]]))
            .fold(String::new(), |s,cs| add4(s,cs));
        let s = if last_chunk == 2 {
            let cs = two2b64([bytes[first_chunks],
                             bytes[first_chunks+1]]);
            add4(s, cs)
        } else if last_chunk == 1 {
            let cs = one2b64(bytes[first_chunks]);
            add4(s, cs)
        } else {
            s
        };
        return s;
    }
}

mod better {
    use cryptopals::code;
    #[allow(dead_code)]
    pub fn hex2base64(hex: &str) -> String {
        code::hex_to_base64(hex)
    }
}

const THEIR_HEX: &str = concat!(
    "49276d206b696c6c696e6720796f757220627261696e206c",
    "696b65206120706f69736f6e6f7573206d757368726f6f6d"
);

fn main() {
    let b64 = manual::hex2base64(THEIR_HEX);
    println!("{}", b64);
}
