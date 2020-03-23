use cryptopals::code;

type Struct = Vec<(String, String)>;

fn kv_parse(inp: &str) -> Struct {
    inp.split('&')
        .map(|kv_str| {
            let mut parts = kv_str.split('=');
            let k = parts.next().unwrap();
            let v = parts.next().unwrap();
            (String::from(k), String::from(v))
        })
        .collect()
}

fn sanitize(inp: &str) -> String {
    inp.chars()
        .filter(|c| *c != '&')
        .filter(|c| *c != '=')
        .collect()
}

fn kv_encode(inp: &Struct) -> String {
    let mut s = String::new();
    let mut it = inp.iter();
    if let Some((k, v)) = it.next() {
        s.push_str(&format!("{}={}", sanitize(k), sanitize(v)));
    }
    for (k, v) in it {
        s.push_str(&format!("&{}={}", sanitize(k), sanitize(v)));
    }
    return s;
}

fn create_struct(email: &str, uid: &str, role: &str) -> Struct {
    let uid = String::from(uid);
    let role = String::from(role);
    let email = String::from(email);
    // Order is important. Using same as in challenge description
    return vec![
        (String::from("email"), email),
        (String::from("uid"), uid),
        (String::from("role"), role),
    ];
}

fn profile_for(email: &str) -> String {
    let stru = create_struct(email, "10", "user");
    return kv_encode(&stru);
}

fn encr_for_email(email: &[u8]) -> Vec<u8> {
    let email = String::from_utf8(Vec::from(email)).expect("Invalid email");
    let profile = profile_for(&email);
    return code::ecb(code::blackbox_aes(), profile.as_bytes());
}

fn decrypt_validate(cipher: &mut [u8]) {
    // Inplace decrypt without touching padding
    code::blackbox_aes().ecb_decr(cipher);
    if let Some(plain) = code::pkcs7_validate(cipher) {
        println!("Padding ok");
        let plain = String::from_utf8(Vec::from(plain)).expect("Bad utf8");
        println!("Got plain string [{}]", plain);
        let kvs = kv_parse(&plain);
        println!("Got key value pairs:");
        for (k,v) in kvs {
            println!("    [{}] = [{}]", k, v);
        }

    } else {
        println!("Bad padding");
    }
}

fn attacker() -> Vec<u8> {
    // Want first plaintext to be:
    // email=abc12@foo.|com&uid=10&role=|user
    // So email is abc12@foo.com
    let email1 = b"abc12@foo.com";

    // Want second plaintext to be:
    // email=0123456789|admin...
    // So email is 0123456789admin
    // The constructed ciphertext will end with the block
    // starting with admin. So we pad the email so it's ok as a last
    // block. |admin|=5, 16-5 = 11 = 0x0b
    let email2 = b"0123456789admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";

    let cipher1 = encr_for_email(email1);
    let cipher2 = encr_for_email(email2);

    // First two blocks of cipher1 gives
    // email=abc12@foo.com&uid=10&role=
    // Second block of cipher2 gives
    // admin(valid padding)
    // Putting it together

    return cipher1
        .iter()
        .take(16 * 2)
        .chain(cipher2.iter().skip(16).take(16))
        .copied()
        .collect();
}

fn main() {
    let mut attacker_cipher = attacker();
    decrypt_validate(&mut attacker_cipher);
}
