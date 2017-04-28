#include <stdio.h>
#include "crypto.h"
#include "protocol.h"
#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <linux/random.h>


int main(){
   generate_and_store_keys();
   mpz_t public_key;
   read_local_public_key_from_file(public_key);
   mpz_t private_key;
   read_local_private_key_from_file(private_key);
   mpz_t key_exp;
   mpz_init_set_ui(key_exp,PUB_KEY_EXP);

   uint8_t token[MAX_DATA_SIZE];
   fillrandom(token, MAX_DATA_SIZE);
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      printf("%02x",token[i]);
   }
   printf("\n");
   uint8_t newtoken[REAL_MAX_DATA_SIZE];
   encrypt_block(token, newtoken, key_exp, public_key);
   printf("\n");
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      printf("%02x",newtoken[i]);
   }
   printf("\n");
   uint8_t newnewtoken[MAX_DATA_SIZE];
   decrypt_block(newtoken, newnewtoken, private_key, public_key);
   printf("\n");
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      printf("%02x",newnewtoken[i]);
   }
   printf("\n");
}
