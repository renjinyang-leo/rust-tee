# rust-tee
This is a library written in rust that implements symmetric encryption in enclave, and the library interface supports mixing with C++ to call trusted functions of rust in the untrusted space of C++
there are some submodules, you should clone repository by parameter `--recursive`


## Prerequisites
* Ubuntu20.04
* Intel SGX Driver
* Intel SGX SDK
* Intel SGX PSW
* [teaclave-sgx-sdk](https://github.com/apache/incubator-teaclave-sgx-sdk)

## Build
**Step1.** You should build Makefile in root directory first, to generate static library writed by rust, codegen the enclave file and compile enclave dynamic library.
**Step2.** Go into app-sample directory, this is a case that apply the lib in C code, you can use the library anywhere by refering the format of the Makefile.

## Submodule List
1. [teaclave-sgx-sdk](https://github.com/apache/incubator-teaclave-sgx-sdk)