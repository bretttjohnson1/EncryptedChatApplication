#include <gmp.h>
#include "bool.h"
#ifndef crypto_header_file
#define crypto_header_file
#define DEFAULT_PRIME_SIZE 128
#define DEFAULT_SMALL_PRIME_SIZE 127
#define BLOCK_SIZE 254
#define ENCRYPED_BLOCK_SIZE 255
#define PUB_KEY_EXP 65537
void gen_rand_prime(mpz_t key,int size);
void generate_keys(mpz_t pub_key,mpz_t priv_key,mpz_t modulus);
void encrypt_block(unsigned char *msg,unsigned char *encrypted_msg,mpz_t pub_key,mpz_t modulus);
void decrypt_block(unsigned char *encrypted_msg,unsigned char *msg, mpz_t priv_key,mpz_t modulus);
void raise_block(unsigned char *original_text,unsigned char *modified_text, mpz_t key,mpz_t modulus,int oldsize,int newsize);
int msg_size_to_encrypted_msg_size(int msg_size);
int encrypted_msg_size_to_msg_size(int msg_size);
void fillrandom(void *val,int sizeinbytes);
void fillzero(void *val,int sizeinbytes);
bool read_key_from_file(mpz_t public_key,char *filename);
void write_key_to_file(mpz_t key,char *filename);
void read_local_public_key_from_file(mpz_t public_key);
void read_local_private_key_from_file(mpz_t private_key);
bool has_generated_key();
void generate_and_store_keys();
#endif
