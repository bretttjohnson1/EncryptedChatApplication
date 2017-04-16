/*
   Brett Johnson
   btj12
   bool.h
   4/16/2017
   This file holds a struct that is boolean
 */
//#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>
#include <math.h>
#include <time.h>
#include "bool.h"
#include "crypto.h"
#include <unistd.h>
#include <linux/random.h>
#include <sys/syscall.h>

const char publickeyfilename[] = "localpublickey.key";
const char privatekeyfilename[] = "localprivatekey.key";


void gen_rand_prime(mpz_t key, int size){
	mpz_init(key);
	bool isprime = false;
	while(!isprime) {
		mpz_set_ui(key,0);
      uint8_t rand_val[size];
      fillrandom(&rand_val,size);
		for(int a =0; a<size; a++) {
			mpz_t offset;
			mpz_init(offset);
			mpz_set_ui(offset,256);
			mpz_pow_ui(offset,offset,a);
			mpz_mul_ui(offset,offset,rand_val[a]);
			mpz_add(key,key,offset);
			mpz_clear(offset);
		}
		isprime = (mpz_probab_prime_p(key,100)==1);
	}
}

void read_local_public_key_from_file(mpz_t public_key){
   read_key_from_file(public_key,(char*)publickeyfilename);
}
void read_local_private_key_from_file(mpz_t private_key){
   read_key_from_file(private_key, (char*)privatekeyfilename);
}
void read_key_from_file(mpz_t key,char *filename){
   mpz_init(key);
   FILE *key_file = fopen(filename,"rb");
   char key_data[ENCRYPED_BLOCK_SIZE];
   fread(key_data,ENCRYPED_BLOCK_SIZE,sizeof(uint8_t),key_file);
   mpz_import(key,ENCRYPED_BLOCK_SIZE,1,sizeof(uint8_t),1,0,key_data);
   fclose(key_file);
}
void write_key_to_file(mpz_t key,char *filename){
   FILE *key_file = fopen(filename,"wb");
   char key_data[ENCRYPED_BLOCK_SIZE];
   mpz_export(key_data,NULL,1,sizeof(uint8_t),1,0,key);
   fwrite(key_data,ENCRYPED_BLOCK_SIZE,sizeof(uint8_t),key_file);
   fclose(key_file);
}
bool has_generated_key(){
   if(access(privatekeyfilename, F_OK)!=-1 && access(publickeyfilename, F_OK)!=-1){
      return true;
   }else{
      return false;
   }
}

void generate_and_store_keys(){
   mpz_t pub_key_exp, private_key, public_key;
   generate_keys(pub_key_exp, private_key, public_key);
   if(has_generated_key()){
      remove(publickeyfilename);
      remove(privatekeyfilename);
   }
   write_key_to_file(public_key,(char *)publickeyfilename);
   write_key_to_file(private_key,(char *)privatekeyfilename);
}

void generate_keys(mpz_t pub_key,mpz_t priv_key,mpz_t modulus){
	mpz_t prime1;
	gen_rand_prime(prime1,DEFAULT_PRIME_SIZE);
	mpz_t prime2;
	gen_rand_prime(prime2,DEFAULT_SMALL_PRIME_SIZE);
	mpz_init(modulus);
	mpz_mul(modulus,prime1,prime2);
	mpz_sub_ui(prime1,prime1,1);
	mpz_sub_ui(prime2,prime2,1);
	mpz_t lambda;
	mpz_init(lambda);
	mpz_lcm(lambda,prime1,prime2);
	mpz_clear(prime1);
	mpz_clear(prime2);
	bool valid_pub_key = false;
	mpz_init(pub_key);
	mpz_set_ui(pub_key,PUB_KEY_EXP);
	while(!valid_pub_key) {
		mpz_t gcd;
		mpz_init(gcd);
		mpz_gcd(gcd,pub_key,lambda);
		if(mpz_cmp_ui(gcd,1)==0) {
			valid_pub_key=true;
		}
		mpz_clear(gcd);
      if(!valid_pub_key)
         mpz_sub_ui(pub_key,pub_key,1);
	}
	mpz_t g_tmp;
	mpz_init(g_tmp);
	mpz_init(priv_key);
	mpz_t t_tmp;
	mpz_init(t_tmp);
	mpz_gcdext(g_tmp,priv_key,t_tmp,pub_key,lambda);
	mpz_clear(g_tmp);
	mpz_clear(t_tmp);
	if(mpz_cmp_ui(priv_key,0)<0) {
		mpz_mod(priv_key,priv_key,lambda);
	}
	mpz_clear(lambda);

}
void encrypt_block(unsigned char *msg,unsigned char *encrypted_msg,mpz_t pub_key,mpz_t modulus){
	raise_block(msg,encrypted_msg,pub_key,modulus,BLOCK_SIZE,ENCRYPED_BLOCK_SIZE);
}
void decrypt_block(unsigned char *encrypted_msg,unsigned char *msg, mpz_t priv_key,mpz_t modulus){
	raise_block(encrypted_msg,msg,priv_key,modulus,ENCRYPED_BLOCK_SIZE,BLOCK_SIZE);
}

void raise_block(unsigned char *original_text,unsigned char *modified_text, mpz_t key,mpz_t modulus,int oldsize,int newsize){
	mpz_t msg_as_mpz;
	mpz_init(msg_as_mpz);
	mpz_set_ui(msg_as_mpz,0);
	mpz_t offset;
	mpz_init(offset);
	mpz_set_ui(offset,1);
	mpz_t raised_val;
	mpz_init(raised_val);
	for(int i = 0; i<oldsize; i++) {
		mpz_mul_ui(raised_val,offset,original_text[i]);
		mpz_add(msg_as_mpz,msg_as_mpz,raised_val);
		mpz_mul_ui(offset,offset,256);
	}
	mpz_clear(raised_val);
	mpz_clear(offset);
	mpz_powm_sec(msg_as_mpz,msg_as_mpz,key,modulus);
	mpz_t offset_small;
	mpz_init(offset);
	mpz_init(offset_small);
	mpz_set_ui(offset,256);
	mpz_set_ui(offset_small,1);
	for(int i = 0; i<newsize; i++) {
		mpz_t bigmod;
		mpz_t smallmod;
		mpz_init(bigmod);
		mpz_init(smallmod);
		mpz_mod(bigmod,msg_as_mpz,offset);
		mpz_mod(smallmod,msg_as_mpz,offset_small);
		mpz_sub(bigmod,bigmod,smallmod);
		mpz_divexact(bigmod,bigmod,offset_small);
		modified_text[i] = mpz_get_ui(bigmod);
		mpz_clear(bigmod);
		mpz_clear(smallmod);
		mpz_mul_ui(offset,offset,256);
		mpz_mul_ui(offset_small,offset_small,256);
	}
	mpz_clear(msg_as_mpz);
	mpz_clear(offset);
	mpz_clear(offset_small);
}


int msg_size_to_encrypted_msg_size(int msg_size){
	return ceil(((double)msg_size)/BLOCK_SIZE)*ENCRYPED_BLOCK_SIZE;
}

int encrypted_msg_size_to_msg_size(int msg_size){
	return ceil(((double)msg_size)/ENCRYPED_BLOCK_SIZE)*BLOCK_SIZE;
}
void fillrandom(void *val,int sizeinbytes){
   FILE *devurandom = fopen("/dev/urandom", "rb");
   fread(val,1,sizeinbytes,devurandom);
   fclose(devurandom);
}
void fillzero(void *val,int sizeinbytes){
   for(int i = 0;i<sizeinbytes;i++){
      ((char*)val)[i] = 0;
   }
}
