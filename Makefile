Rust_Enclave_Name := libenclave.a
Rust_Enclave_Files := $(wildcard src/*.rs)
Rust_Target_Path := $(CURDIR)/../../../xargo

ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
export MITIGATION_CVE_2020_0551=LOAD
else ifeq ($(MITIGATION-CVE-2020-0551), CF)
export MITIGATION_CVE_2020_0551=CF
endif

######## CUSTOM PATH ########
CUSTOM_EDL_PATH := ./sgx-sdk/edl
CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_COMMON_PATH := ./sgx-sdk/common

######## SGX SDK Settings ########

SGX_SDK ?= /opt/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

include sgx-sdk/buildenv.mk

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

SGX_COMMON_CFLAGS += -fstack-protector

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Crypto_Library_Name := sgx_tcrypto
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I./enclave -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Service_Library_Name) -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=Enclave.lds \
	$(ENCLAVE_LDFLAGS)

RustEnclave_Name := enclave/enclave.so
Signed_RustEnclave_Name := bin/enclave.signed.so


.PHONY: all

all: $(Rust_Enclave_Name) $(Enclave_EDL_Files) $(Signed_RustEnclave_Name) enclave/Enclave_u.o

######## Enclave Library ########

$(Rust_Enclave_Name): $(Rust_Enclave_Files)
	mkdir -p lib
ifeq ($(XARGO_SGX), 1)
	RUST_TARGET_PATH=$(Rust_Target_Path) xargo build --target x86_64-unknown-linux-sgx --release
	cp ./target/x86_64-unknown-linux-sgx/release/libcryptoenclave.a ../lib/libenclave.a
else
	cargo build --release
	cp ./target/release/libcryptoenclave.a ./lib/libenclave.a
endif

######## EDL Objects ########
Enclave_EDL_Files := enclave/Enclave_t.c enclave/Enclave_t.h app/Enclave_u.c app/Enclave_u.h

$(Enclave_EDL_Files):
	mkdir -p enclave
	$(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir enclave
	$(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir enclave
	@echo "GEN  =>  $(Enclave_EDL_Files)"


######## Enclave Objects ########
App_Include_Paths := -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

enclave/Enclave_t.o: enclave/Enclave_t.c
	@$(CC) $(RustEnclave_Compile_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave/Enclave_t.o
	@$(CXX) enclave/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name) sgx_ustdc
	mkdir -p bin
	cp sgx-sdk/sgx_ustdc/libsgx_ustdc.a ./lib
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config Enclave.config.xml
	@echo "SIGN =>  $@"

enclave/Enclave_u.o: enclave/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"



.PHONY: sgx_ustdc
sgx_ustdc:
	$(MAKE) -C sgx-sdk/sgx_ustdc/ 2> /dev/null


.PHONY: clean
clean:
	@rm -rf ./target ./bin ./lib ./enclave