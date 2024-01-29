######## CUSTOM ARGUMENT ########
include ../sgx-sdk/buildenv.mk
CUSTOM_EDL_PATH := ../sgx-sdk/edl
CUSTOM_LIBRARY_PATH := ../lib
CUSTOM_ENCLAVE_LIBRARY := ../enclave/Enclave_u.o
App_C_Files := $(wildcard ./*.c)


######## SGX SDK Settings ########
SGX_SDK ?= /opt/sgxsdk
SGX_MODE ?= HW

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


######## APP Settings ########
ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Include_Paths := -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -L$(CUSTOM_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread
ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Link_Flags += -lsgx_ustdc

App_C_Objects := $(App_C_Files:.c=.o)

App_Name := bin/app

######## APP Settings ########

.PHONY: all

all: $(App_Name)

$(App_C_Objects): $(App_C_Files)
	@$(CXX) $(App_C_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(App_C_Objects)
	mkdir -p bin
	$(CXX) $(CUSTOM_ENCLAVE_LIBRARY) $(App_C_Objects) -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean
clean:
	@rm -rf ./bin
	@rm -r $(App_C_Objects)