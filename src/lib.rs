#![crate_name = "cryptoenclave"]
#![crate_type = "staticlib"]

#![allow(dead_code)]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_trts;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use sgx_tcrypto::*;
use sgx_tstd::vec::Vec;
use sgx_tstd::slice;
use sgx_tstd::ptr;

#[no_mangle]
pub extern "C" fn aes_ctr_128_encrypt(key: &[u8;16],
                                      plaintext: *const u8,
                                      text_len: usize,
                                      ciphertext: *mut u8) -> sgx_status_t {
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, text_len) };
    let mut ciphertext_vec: Vec<u8> = vec![0; text_len];
    if plaintext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let ciphertext_slice = &mut ciphertext_vec[..];
    let mut ctr_vec = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76];

    let result = rsgx_aes_ctr_encrypt(key,
                                                                &plaintext_slice,
                                                                &mut ctr_vec,
                                                                8,
                                                                ciphertext_slice
                                                                );
    match result {
        Err(x) => { return x; }
        Ok(()) => {
            unsafe{
                ptr::copy_nonoverlapping(ciphertext_slice.as_ptr(),
                                            ciphertext,
                                            text_len);
            }
        }
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn aes_ctr_128_decrypt(key: &[u8;16],
                                      ciphertext: *const u8,
                                      text_len: usize,
                                      plaintext: *mut u8) -> sgx_status_t {
    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, text_len) };
    let mut plaintext_vec: Vec<u8> = vec![0; text_len];
    if ciphertext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let plaintext_slice = &mut plaintext_vec[..];

    let mut ctr_vec = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76];
    let result = rsgx_aes_ctr_decrypt(key,
                                                            &ciphertext_slice,
                                                            &mut ctr_vec,
                                                            8,
                                                            plaintext_slice);
    match result {
        Err(x) => { return x; }
        Ok(()) => {
            unsafe {
                ptr::copy_nonoverlapping(plaintext_slice.as_ptr(),
                                            plaintext,
                                            text_len);
            }
        }
    }
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn aes_gcm_128_encrypt(key: &[u8;16],
                                      plaintext: *const u8,
                                      text_len: usize,
                                      iv: &[u8;12],
                                      ciphertext: *mut u8,
                                      mac: &mut [u8;16]) -> sgx_status_t {
    let plaintext_slice = unsafe { slice::from_raw_parts(plaintext, text_len) };
    let mut ciphertext_vec: Vec<u8> = vec![0; text_len];

    let aad_array: [u8; 0] = [0; 0];
    let mut mac_array: [u8; SGX_AESGCM_MAC_SIZE] = [0; SGX_AESGCM_MAC_SIZE];

    if plaintext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let ciphertext_slice = &mut ciphertext_vec[..];

    let result = rsgx_rijndael128GCM_encrypt(key,
                                             &plaintext_slice,
                                             iv,
                                             &aad_array,
                                             ciphertext_slice,
                                             &mut mac_array);

    match result {
        Err(x) => { return x; }
        Ok(()) => {
            unsafe{
                ptr::copy_nonoverlapping(ciphertext_slice.as_ptr(),
                                         ciphertext,
                                         text_len);
            }
            *mac = mac_array;
        }
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn aes_gcm_128_decrypt(key: &[u8;16],
                                      ciphertext: *const u8,
                                      text_len: usize,
                                      iv: &[u8;12],
                                      mac: &[u8;16],
                                      plaintext: *mut u8) -> sgx_status_t {

    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, text_len) };
    let mut plaintext_vec: Vec<u8> = vec![0; text_len];
    let aad_array: [u8; 0] = [0; 0];

    if ciphertext_slice.len() != text_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    let plaintext_slice = &mut plaintext_vec[..];

    let result = rsgx_rijndael128GCM_decrypt(key,
                                             &ciphertext_slice,
                                             iv,
                                             &aad_array,
                                             mac,
                                             plaintext_slice);

    match result {
        Err(x) => { return x; }
        Ok(()) => {
            unsafe {
                ptr::copy_nonoverlapping(plaintext_slice.as_ptr(),
                                         plaintext,
                                         text_len);
            }
        }
    }

    sgx_status_t::SGX_SUCCESS
}