use crate::code;

use lazy_static::*;

lazy_static! {
    static ref HIDDEN_AES: code::aes128::Aes128 = {
        let key = code::rnd(16);
        code::aes128::Aes128::new(&key)
    };
}

pub fn blackbox() -> &'static code::aes128::Aes128 {
    return &HIDDEN_AES;
}
