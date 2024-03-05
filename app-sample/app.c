#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <memory.h>
#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "app.h"
#include "../enclave/Enclave_u.h"

int aes_gcm_128();
int aes_ctr_128();

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

int initialize_enclave(void)
{
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    /* call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    printf("[+] global_eid: %ld\n", global_eid);
    return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{

    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    if (aes_ctr_128() == -1) { 
        printf("error: aes-ctr-128 test failed!\n");
        return -1; 
    };
    //if (aes_gcm_128() == -1) { return -1; };

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}

int aes_ctr_128() {
    srand((unsigned)time(NULL));
    // 进行1000次测试
    for (int i = 0; i < 1000; i++) {
        int64_t num = rand()%2000000 - 1000000;
        uint8_t plaintext[16] = {0};
        memcpy(plaintext, &num, sizeof(int64_t));

        char key[] = "b00d44fdbec34270";
        uint8_t aes_ctr_key[16] = {0};
        memcpy(aes_ctr_key, (uint8_t *)key, sizeof(aes_ctr_key));

        uint8_t ciphertext[16] = {0};

        sgx_status_t enclave_ret = SGX_SUCCESS;
        sgx_status_t sgx_ret = SGX_SUCCESS;
        sgx_ret = aes_ctr_128_encrypt(global_eid,
                                    &enclave_ret,
                                    aes_ctr_key,
                                    plaintext,
                                    16,
                                    ciphertext);

        if(sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }

        if(enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        uint8_t decrypted_text[16] = {0};
        sgx_ret = aes_ctr_128_decrypt(global_eid,
                                    &enclave_ret,
                                    aes_ctr_key,
                                    ciphertext,
                                    16,
                                    decrypted_text);
        
        if(sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }
        if(enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        int64_t de_num;
        memcpy(&de_num, decrypted_text, sizeof(int64_t));
        if (de_num == num) {
            printf("aes-ctr-128 test#%d pass! num = %ld\n", i+1, num);
        } else {
            printf("aes-ctr-128 test#%d failed!\n", i+1);
            return -1;
        }
    }

    return 0;
}

int aes_gcm_128(){
    printf("[+] Starting aes-gcm-128 encrypt calculation\n");
    uint8_t aes_gcm_plaintext[16] = {0};
    uint8_t aes_gcm_key[16] = {0};
    uint8_t aes_gcm_iv[12] = {0};
    uint8_t aes_gcm_ciphertext[16] = {0};

    uint8_t aes_gcm_mac[16] = {0};
    sgx_status_t enclave_ret = SGX_SUCCESS;
    sgx_status_t sgx_ret = SGX_SUCCESS;

    printf("[+] aes-gcm-128 expected ciphertext: %s\n",
           "0388dace60b6a392f328c2b971b2fe78");
    sgx_ret = aes_gcm_128_encrypt(global_eid,
                                  &enclave_ret,
                                  aes_gcm_key,
                                  aes_gcm_plaintext,
                                  16,
                                  aes_gcm_iv,
                                  aes_gcm_ciphertext,
                                  aes_gcm_mac);

    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }

    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    printf("[+] aes-gcm-128 ciphertext is: ");
    int i;
    for(i = 0; i < 16; i ++) {
        printf("%02x", aes_gcm_ciphertext[i]);
    }
    printf("\n");

    printf("[+] aes-gcm-128 result mac is: ");
    for(i = 0; i < 16; i ++) {
        printf("%02x", aes_gcm_mac[i]);
    }
    printf("\n");

    printf("[+] Starting aes-gcm-128 decrypt calculation\n");
    uint8_t aes_gcm_decrypted_text[16] = {0};
    sgx_ret = aes_gcm_128_decrypt(global_eid,
                                  &enclave_ret,
                                  aes_gcm_key,
                                  aes_gcm_ciphertext,
                                  16,
                                  aes_gcm_iv,
                                  aes_gcm_mac,
                                  aes_gcm_decrypted_text);

    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }
    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    printf("[+] aes-gcm-128 decrypted plaintext is: ");
    for(i = 0; i < 16; i ++) {
        printf("%02x", aes_gcm_decrypted_text[i]);
    }
    printf("\n");
    return 0;
}