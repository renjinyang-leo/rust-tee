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

char *generate_random_string(int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const size_t max_index = (int)(sizeof(charset) - 1);
    char *random_string = (char *)malloc(length + 1);

    if (random_string) {
        for (int i = 0; i < length; ++i) {
            random_string[i] = charset[rand() % max_index];
        }
        random_string[length] = '\0';
    }
    return random_string;
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

static int test_ciphertext_gen()
{
    char key[] = "b00d44fdbec34270";
    uint8_t aes_ctr_key[16] = {0};
    memcpy(aes_ctr_key, (uint8_t *)key, sizeof(aes_ctr_key));

    int nbits = 62;
    int64_t rt = rand() % ((uint64_t)1 << nbits);
    uint8_t plaintext[8] = {0};
    memcpy(plaintext, &rt, sizeof(int64_t));

    uint8_t ciphertext[8] = {0};

    sgx_status_t enclave_ret = SGX_SUCCESS;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_ret = aes_ctr_128_encrypt(global_eid,
                                  &enclave_ret,
                                  aes_ctr_key,
                                  plaintext,
                                  8,
                                  ciphertext);

    if(sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }

    if(enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }
    return 0;
}

int experiment_1() {
    printf("tee benchmark experiment-1 \n");
    int total_num = 50;  //实验进行总数

    clock_t start,end;     //定义clock_t变量
    start = clock();       //开始时间
    for (int i = 1; i <= total_num; i++) {
        for (int j = 0; j < 100; j++) {
            if (test_ciphertext_gen() != 0) return -1;
        }
    }
    end = clock();   //结束时间
    printf("实验一，数据量100, time = %lf ms\n", (double)(end-start)/1000/total_num);   //输出时间（单位:mｓ）

    start = clock();       //开始时间
    for (int i = 1; i <= total_num; i++) {
        for (int j = 0; j < 500; j++) {
            if (test_ciphertext_gen() != 0) return -1;
        }
    }
    end = clock();   //结束时间
    printf("实验一，数据量500, time = %lf ms\n", (double)(end-start)/1000/total_num);   //输出时间（单位:mｓ）

    start = clock();       //开始时间
    for (int i = 1; i <= total_num; i++) {
        for (int j = 0; j < 1000; j++) {
            if (test_ciphertext_gen() != 0) return -1;
        }
    }
    end = clock();   //结束时间
    printf("实验一，数据量1000, time = %lf ms\n", (double)(end-start)/1000/total_num);   //输出时间（单位:mｓ）

    start = clock();       //开始时间
    for (int i = 1; i <= total_num; i++) {
        for (int j = 0; j < 1500; j++) {
            if (test_ciphertext_gen() != 0) return -1;
        }
    }
    end = clock();   //结束时间
    printf("实验一，数据量1500, time = %lf ms\n", (double)(end-start)/1000/total_num);   //输出时间（单位:mｓ）

    start = clock();       //开始时间
    for (int i = 1; i <= total_num; i++) {
        for (int j = 0; j < 10000; j++) {
            if (test_ciphertext_gen() != 0) return -1;
        }
    }
    end = clock();   //结束时间
    printf("实验一，数据量10000, time = %lf ms\n", (double)(end-start)/1000/total_num);   //输出时间（单位:mｓ）
}

int experiment_2() {
    printf("tee benchmark experiment-2 \n");
    int lens[5] = {4, 8, 16, 32};
    for (int i = 0; i < 4; i++) {
        uint32_t length = lens[i];
        sgx_status_t enclave_ret = SGX_SUCCESS;
        sgx_status_t sgx_ret = SGX_SUCCESS;
        int total_num = 50;  //实验进行总数

        clock_t start,end;     //定义clock_t变量
        start = clock();       //开始时间
        for (int j = 1; j <= total_num; j++) {
            for (int k = 0; k < 500; k++) {
                char key[] = "b00d44fdbec34270";
                uint8_t aes_ctr_key[16] = {0};
                memcpy(aes_ctr_key, (uint8_t *)key, sizeof(aes_ctr_key));
                uint8_t *plaintext = (uint8_t *)generate_random_string(length);
                uint8_t *ciphertext = (uint8_t *)malloc(length);
                sgx_ret = aes_ctr_128_encrypt(global_eid,
                                              &enclave_ret,
                                              aes_ctr_key,
                                              plaintext,
                                              length,
                                              ciphertext);

                free(plaintext);
                free(ciphertext);

                if (sgx_ret != SGX_SUCCESS) {
                    print_error_message(sgx_ret);
                    return -1;
                }

                if (enclave_ret != SGX_SUCCESS) {
                    print_error_message(enclave_ret);
                    return -1;
                }
            }
        }
        end = clock();   //结束时间
        printf("实验二，数据量500, char len = %d, time = %lf ms\n", length, (double)(end-start)/1000/total_num);   //输出时间（单位:mｓ）
    }
    return 0;
}

int experiment_3() {
    printf("tee benchmark experiment-3 \n");
    char key[] = "b00d44fdbec34270";
    uint8_t aes_ctr_key[16] = {0};
    memcpy(aes_ctr_key, (uint8_t *)key, sizeof(aes_ctr_key));
    int nbits = 62, res = 0;
    int total_num = 50;  //实验进行总数

    int64_t num1 = rand() % ((uint64_t)1 << nbits);
    int64_t num2 = rand() % ((uint64_t)1 << nbits);
    uint8_t plaintext1[8] = {0};
    uint8_t plaintext2[8] = {0};
    memcpy(plaintext1, &num1, sizeof(int64_t));
    memcpy(plaintext2, &num2, sizeof(int64_t));

    uint8_t ciphertext1[8] = {0};
    uint8_t ciphertext2[8] = {0};

    sgx_status_t enclave_ret = SGX_SUCCESS;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_ret = aes_ctr_128_encrypt(global_eid,
                                  &enclave_ret,
                                  aes_ctr_key,
                                  plaintext1,
                                  8,
                                  ciphertext1);

    if (sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }

    if (enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    sgx_ret = aes_ctr_128_encrypt(global_eid,
                                  &enclave_ret,
                                  aes_ctr_key,
                                  plaintext2,
                                  8,
                                  ciphertext2);

    if (sgx_ret != SGX_SUCCESS) {
        print_error_message(sgx_ret);
        return -1;
    }
    if (enclave_ret != SGX_SUCCESS) {
        print_error_message(enclave_ret);
        return -1;
    }

    clock_t start,end;     //定义clock_t变量
    start = clock();       //开始时间
    for (int i = 1; i <= total_num; i++) {
        for (int j = 0; j < 20000; j++) {
            int8_t cmp;
            sgx_ret = aes_ctr_128_int64_compare(global_eid,
                                                &enclave_ret,
                                                aes_ctr_key,
                                                ciphertext1,
                                                ciphertext2,
                                                8,
                                                &cmp);
            if(sgx_ret != SGX_SUCCESS) {
                print_error_message(sgx_ret);
                return -1;
            }
            if(enclave_ret != SGX_SUCCESS) {
                print_error_message(enclave_ret);
                return -1;
            }
        }
    }
    end = clock();   //结束时间
    printf("实验三，数据量20000, time = %lf ms\n", (double)(end-start)/1000/total_num);   //输出时间（单位:mｓ）
    return  0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{

    (void)(argc);
    (void)(argv);


    // Initialize the enclave
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    /*
    if (aes_ctr_128() == -1) { 
        printf("error: aes-ctr-128 test failed!\n");
        return -1; 
    };
     */
    //if (aes_gcm_128() == -1) { return -1; };

    if (experiment_1() == -1) {
        printf("error: experiment_1 failed!\n");
        return -1;
    }

    if (experiment_2() == -1) {
        printf("error: experiment_2 failed!\n");
        return -1;
    }

    if (experiment_3() == -1) {
        printf("error: experiment_3 failed!\n");
        return -1;
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}

int aes_ctr_128() {
    srand((unsigned)time(NULL));
    char key[] = "b00d44fdbec34270";
    uint8_t aes_ctr_key[16] = {0};
    memcpy(aes_ctr_key, (uint8_t *)key, sizeof(aes_ctr_key));
    
    // 进行1000次测试
    int total_test=1000, failed_test = 0;
    for (int i = 0; i < total_test; i++) {
        int64_t num = rand()%2000000 - 1000000;
        uint8_t plaintext[8] = {0};
        memcpy(plaintext, &num, sizeof(int64_t));

        uint8_t ciphertext[8] = {0};

        sgx_status_t enclave_ret = SGX_SUCCESS;
        sgx_status_t sgx_ret = SGX_SUCCESS;
        sgx_ret = aes_ctr_128_encrypt(global_eid,
                                    &enclave_ret,
                                    aes_ctr_key,
                                    plaintext,
                                    8,
                                    ciphertext);

        if(sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }

        if(enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        uint8_t decrypted_text[8] = {0};
        sgx_ret = aes_ctr_128_decrypt(global_eid,
                                    &enclave_ret,
                                    aes_ctr_key,
                                    ciphertext,
                                    8,
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
            //printf("aes-ctr-128 test#%d pass! num = %ld\n", i+1, num);
        } else {
            failed_test++;
            printf("aes-ctr-128 test#%d failed!\n", i+1);
        }
    }
    if (failed_test != 0) printf("aes-ctr-128 encrypt and decrypt test failed count = %d, failed rate = %lf\n", failed_test, failed_test*1.0/total_test);
    else printf("aes-ctr-128 encrypt and decrypt test all passed\n");
    printf("+++++++++++++++++++++++++++++++++++++++++++++\n");
    
    // 进行1000次测试
    total_test=1000, failed_test = 0;
    for (int i = 0; i < total_test; i++) {
        int64_t num1 = rand()%2000000 - 1000000;
        int64_t num2 = rand()%2000000 - 1000000;
        uint8_t plaintext1[8] = {0};
        uint8_t plaintext2[8] = {0};
        memcpy(plaintext1, &num1, sizeof(int64_t));
        memcpy(plaintext2, &num2, sizeof(int64_t));

        uint8_t ciphertext1[8] = {0};
        uint8_t ciphertext2[8] = {0};

        sgx_status_t enclave_ret = SGX_SUCCESS;
        sgx_status_t sgx_ret = SGX_SUCCESS;
        sgx_ret = aes_ctr_128_encrypt(global_eid,
                                    &enclave_ret,
                                    aes_ctr_key,
                                    plaintext1,
                                    8,
                                    ciphertext1);

        if (sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }

        if (enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        sgx_ret = aes_ctr_128_encrypt(global_eid,
                                    &enclave_ret,
                                    aes_ctr_key,
                                    plaintext2,
                                    8,
                                    ciphertext2);

        if (sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }
        if (enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        int8_t cmp;
        sgx_ret = aes_ctr_128_int64_compare(global_eid,
                                    &enclave_ret,
                                    aes_ctr_key,
                                    ciphertext1,
                                    ciphertext2,
                                    8,
                                    &cmp);
        
        if(sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }
        if(enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        if ((num1 == num2 && cmp == 0) || (num1 > num2 && cmp == 1) || (num1 < num2 && cmp == -1)) {
            //printf("aes-ctr-128 test#%d pass! num = %ld\n", i+1, num);
        } else {
            failed_test++;
            printf("aes-ctr-128 test#%d failed!\n", i+1);
        }
    }
    if (failed_test != 0) printf("aes-ctr-128 compare test failed count = %d, failed rate = %lf\n", failed_test, failed_test*1.0/total_test);
    else printf("aes-ctr-128 compare test all passed\n");
    printf("+++++++++++++++++++++++++++++++++++++++++++++\n");

    for (int i = 0; i < total_test; i++) {
        int64_t length = rand()%500 + 1;
        uint8_t *plaintext = (uint8_t *)generate_random_string(length);

        uint8_t *ciphertext = (uint8_t *)malloc(length);

        sgx_status_t enclave_ret = SGX_SUCCESS;
        sgx_status_t sgx_ret = SGX_SUCCESS;
        sgx_ret = aes_ctr_128_encrypt(global_eid,
                                      &enclave_ret,
                                      aes_ctr_key,
                                      plaintext,
                                      length,
                                      ciphertext);

        if(sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }

        if(enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        uint8_t *decrypted_text = (uint8_t *)malloc(length);;
        sgx_ret = aes_ctr_128_decrypt(global_eid,
                                      &enclave_ret,
                                      aes_ctr_key,
                                      ciphertext,
                                      length,
                                      decrypted_text);

        if(sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }
        if(enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        bool fail = false;
        for (int i = 0; i < length; i++) {
            if (decrypted_text[i] != plaintext[i]) {
                fail = true;
                break;
            }
        }
        if (!fail) {
            //printf("aes-ctr-128 test#%d pass! num = %ld\n", i+1, num);
        } else {
            failed_test++;
            printf("aes-ctr-128 varchar test#%d failed!\n", i+1);
        }
        free(plaintext);
        free(ciphertext);
        free(decrypted_text);
    }
    if (failed_test != 0) printf("aes-ctr-128 encrypt and decrypt test failed count = %d, failed rate = %lf\n", failed_test, failed_test*1.0/total_test);
    else printf("aes-ctr-128 varchar encrypt and decrypt test all passed\n");
    printf("+++++++++++++++++++++++++++++++++++++++++++++\n");

    // 进行1000次测试
    total_test=1000, failed_test = 0;
    for (int i = 0; i < total_test; i++) {
        int64_t length_1 = rand()%500 + 1;
        int64_t length_2 = rand()%500 + 1;
        uint8_t *plaintext1 = (uint8_t *)generate_random_string(length_1);
        uint8_t *plaintext2 = (uint8_t *)generate_random_string(length_2);

        uint8_t *ciphertext1 = (uint8_t *)malloc(length_1);
        uint8_t *ciphertext2 = (uint8_t *)malloc(length_2);

        sgx_status_t enclave_ret = SGX_SUCCESS;
        sgx_status_t sgx_ret = SGX_SUCCESS;
        sgx_ret = aes_ctr_128_encrypt(global_eid,
                                      &enclave_ret,
                                      aes_ctr_key,
                                      plaintext1,
                                      length_1,
                                      ciphertext1);

        if (sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }

        if (enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        sgx_ret = aes_ctr_128_encrypt(global_eid,
                                      &enclave_ret,
                                      aes_ctr_key,
                                      plaintext2,
                                      length_2,
                                      ciphertext2);

        if (sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }
        if (enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        int8_t cmp;
        sgx_ret = aes_ctr_128_str_compare(global_eid,
                                            &enclave_ret,
                                            aes_ctr_key,
                                            ciphertext1,
                                            ciphertext2,
                                            length_1,
                                            length_2,
                                            &cmp);

        if(sgx_ret != SGX_SUCCESS) {
            print_error_message(sgx_ret);
            return -1;
        }
        if(enclave_ret != SGX_SUCCESS) {
            print_error_message(enclave_ret);
            return -1;
        }

        if ((strcmp((char *)plaintext1, (char *)plaintext2) == 0 && cmp == 0) || (strcmp((char *)plaintext1, (char *)plaintext2) > 0 && cmp == 1) || (strcmp((char *)plaintext1, (char *)plaintext2) < 0 && cmp == -1)) {
            //printf("aes-ctr-128 test#%d pass! num = %ld\n", i+1, num);
        } else {
            failed_test++;
            printf("aes-ctr-128 varchar compare test#%d failed!\n", i+1);
        }
        free(plaintext1);
        free(plaintext2);
        free(ciphertext1);
        free(ciphertext2);
    }
    if (failed_test != 0) printf("aes-ctr-128 compare test failed count = %d, failed rate = %lf\n", failed_test, failed_test*1.0/total_test);
    else printf("aes-ctr-128 varchar compare test all passed\n");

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