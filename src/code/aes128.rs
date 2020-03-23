
mod ffiaes {
    #[link(name = "appcrypaes", kind = "static")]
    extern "C" {
        pub fn key_sched(roundkeys: *mut u8, key: *const u8);
        pub fn encrypt_block(block: *mut u8, roundkeys: *const u8);
        pub fn decrypt_block(block: *mut u8, roundkeys: *const u8);
    }
}


pub const BLOCKSIZE: usize = 16;
const ROUNDS: usize = 10;
const ROUNDKEYS: usize = ROUNDS + 1;
const ROUNDKEYS_SIZE: usize = ROUNDKEYS * BLOCKSIZE;

pub struct Aes128([u8;ROUNDKEYS_SIZE]);


impl Aes128 {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == 128/8);
        let mut rkeys = [0u8;ROUNDKEYS_SIZE];
        unsafe {
            ffiaes::key_sched(rkeys.as_mut_ptr(), key.as_ptr());
        }
        Self(rkeys)
    }

    pub fn blocksize() -> usize {
        BLOCKSIZE
    }

    pub fn encr(&self, block: &mut [u8]) {
        assert!(block.len() == BLOCKSIZE);
        let Self(roundkeys) = self;
        unsafe {
            ffiaes::encrypt_block(block.as_mut_ptr(), roundkeys.as_ptr());
        }
    }

    pub fn decr(&self, block: &mut [u8]) {
        assert!(block.len() == BLOCKSIZE);
        let Self(roundkeys) = self;
        unsafe {
            ffiaes::decrypt_block(block.as_mut_ptr(), roundkeys.as_ptr());
        }
    }

    pub fn cbc_encr(&self, iv: &[u8], buf: &mut Vec<u8>) {
        use crate::code;
        if buf.len() == 0 {
            return;
        }

        assert!(iv.len() == BLOCKSIZE);
        code::pkcs7_pad(buf, BLOCKSIZE as u8);

        let mut prev = [0u8; BLOCKSIZE];
        memcpy(&mut prev, iv);

        for blk in buf.chunks_mut(BLOCKSIZE) {
            code::block_xor(blk, &prev);
            self.encr(blk);
            memcpy(&mut prev, blk);
        }
    }

    pub fn cbc_decr(&self, iv: &[u8], buf: &mut [u8]) {
        use crate::code;
        if buf.len() == 0 {
            return;
        }

        assert!(iv.len() == BLOCKSIZE);
        assert!(buf.len() % BLOCKSIZE == 0);

        let mut prev = [0u8; BLOCKSIZE];
        memcpy(&mut prev, iv);

        for blk in buf.chunks_mut(BLOCKSIZE) {
            let mut this_cipher = [0u8; BLOCKSIZE];
            memcpy(&mut this_cipher, blk);
            self.decr(blk);
            code::block_xor(blk, &prev);
            memcpy(&mut prev, &this_cipher);
        }
    }

    pub fn ecb_encr(&self, buf: &mut Vec<u8>) {
        use crate::code;
        code::pkcs7_pad(buf, BLOCKSIZE as u8);
        for blk in buf.chunks_mut(BLOCKSIZE) {
            self.encr(blk);
        }
    }

    pub fn ecb_decr(&self, buf: &mut [u8]) {
        assert!(buf.len() % BLOCKSIZE == 0);
        for blk in buf.chunks_mut(BLOCKSIZE) {
            self.decr(blk);
        }
    }

    /// Inplace encr/decr
    pub fn ctr_inplace(&self, nonce: u64, buf: &mut[u8]) {
        Aes128Ctr::inplace(self, nonce, buf);
    }
}

//pub struct Aes128(aes::Aes128,[u8;ROUNDKEYS_SIZE])
struct Aes128Ctr<'a> {
    aes: &'a Aes128,
    // Top 64 bits are nonce, bottom 64 bits are counter
    state: [u8;BLOCKSIZE]
}

impl<'a> Aes128Ctr<'a> {
    fn incr(&mut self) {
        // OBS: The ctr wraps without warning
        for i in (BLOCKSIZE/2)..BLOCKSIZE {
            if self.state[i] < u8::max_value() {
                self.state[i] += 1;
                break;
            } else {
                self.state[i] = 0;
            }
        }
    }

    /// Gets next keystream block and updates internal state
    /// Writes keystream block to `buf`
    fn keystream_block(&mut self, buf: &mut [u8]) {
        memcpy(buf, &self.state);
        self.aes.encr(buf);
        self.incr();
    }

    fn new(aes: &'a Aes128, nonce: u64) -> Self {
        assert!(BLOCKSIZE == 2*64/8);
        // ctr automatically set to 0:
        let mut state = [0;BLOCKSIZE];
        // Little endian -> least sig byte first
        let mask = 0x00000000000000FF;
        state[0] = ((nonce >> 0*8) & mask) as u8;
        state[1] = ((nonce >> 1*8) & mask) as u8;
        state[2] = ((nonce >> 2*8) & mask) as u8;
        state[3] = ((nonce >> 3*8) & mask) as u8;
        state[4] = ((nonce >> 4*8) & mask) as u8;
        state[5] = ((nonce >> 5*8) & mask) as u8;
        state[6] = ((nonce >> 6*8) & mask) as u8;
        state[7] = ((nonce >> 7*8) & mask) as u8;

        return Self { aes, state };
    }

    /// Inplace encrypt/decrypt
    fn inplace(aes: &'a Aes128, nonce: u64, buf: &mut[u8]) {
        use crate::code;
        let mut ctr = Self::new(aes, nonce);
        let mut keystream = [0; BLOCKSIZE];
        let whole_blocks = buf.len() / BLOCKSIZE;
        for i in 0..whole_blocks {
            let blk_beg = i * BLOCKSIZE;
            let blk_end = blk_beg + BLOCKSIZE;
            let blk = &mut buf[blk_beg..blk_end];
            ctr.keystream_block(&mut keystream);
            code::block_xor(blk, &keystream);
        }
        let remaining_len = buf.len() % BLOCKSIZE;
        if remaining_len > 0 {
            let blk = code::lastn_mut(buf, remaining_len);
            ctr.keystream_block(&mut keystream);
            code::block_xor(blk, &keystream[..remaining_len]);
        }
    }

}


fn memcpy(dst: &mut [u8], src: &[u8]) {
    assert!(dst.len() == src.len());
    for (i,x) in src.iter().enumerate() {
        dst[i] = *x;
    }
}


