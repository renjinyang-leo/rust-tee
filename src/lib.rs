#![allow(dead_code)]
extern crate crypto;
extern crate rand;

use crypto::{symmetriccipher::{Encryptor, Decryptor}, blockmodes, buffer::{self, BufferResult, WriteBuffer, ReadBuffer}};
use rand::{OsRng, Rng};

struct AesEcb {
    encryptor: Box<dyn Encryptor>,
    decryptor: Box<dyn Decryptor>,
}

impl AesEcb {
    pub fn new() -> Self {
        let mut key: [u8; 32] = [0; 32];
        let mut rng = OsRng::new().ok().unwrap();
        rng.fill_bytes(&mut key);
        let encryptor = crypto::aes::ecb_encryptor(crypto::aes::KeySize::KeySize256, &key, blockmodes::PkcsPadding);
        let decryptor = crypto::aes::ecb_decryptor(crypto::aes::KeySize::KeySize256, &key, blockmodes::PkcsPadding);
        Self {
            encryptor,
            decryptor
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(plaintext);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        
        loop {
            let result = self.encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
            ciphertext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
    
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
        ciphertext
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            let result = self.decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
            plaintext.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
        plaintext
    }

}

#[cfg(test)]
mod tests {
    use crate::AesEcb;

    #[test]
    fn test() {
        let data = "this is a test plaintext";
        let mut aes_ecb = AesEcb::new();
        let cipher = aes_ecb.encrypt(data.as_bytes());
        let plain = aes_ecb.decrypt(&cipher);
        assert!(plain == data.as_bytes().to_vec());
    }
}
