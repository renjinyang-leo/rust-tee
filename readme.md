# rust-tee
This is a library written in rust that implements symmetric encryption in enclave, and the library interface supports mixing with C++ to call trusted functions of rust in the untrusted space of C++
## Prerequisites
* Ubuntu20.04
* Intel SGX Driver
* Intel SGX SDK
* Intel SGX PSW
* [teaclave-sgx-sdk](https://github.com/apache/incubator-teaclave-sgx-sdk)