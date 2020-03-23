use crate::code;

use lazy_static::*;

lazy_static! {
    //static ref RND_KEY: Vec<u8> = code::rnd(16);
    static ref HIDDEN_AES: code::myaes::Aes128 = {
        let key = code::rnd(16);
        code::myaes::Aes128::new(&key)
    };
}

pub fn aes() -> &'static code::myaes::Aes128 {
    return &HIDDEN_AES;
}
