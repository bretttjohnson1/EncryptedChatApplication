#include <stdio.h>
#include "crypto.h"
#include "protocol.h"
#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <linux/random.h>


int main(){
   mpz_t pub_key,priv_key,modulus;
   generate_keys(pub_key,priv_key,modulus);
   gmp_printf("Public Key:%Zd\nPrivate Key:%Zd\nModulus:    %Zd\n",pub_key,priv_key,modulus);
   unsigned char *msg = calloc(MAX_DATA_SIZE,1);
   for(int i = 0;i<MAX_DATA_SIZE;i++)msg[i] = 'a'+ i%25;
   unsigned char *encrypted = calloc(ENCRYPED_BLOCK_SIZE,1);
   unsigned char *recoveredtext =  calloc(BLOCK_SIZE,1);
   printf("Modulus_bits: %ld\n", mpz_sizeinbase(modulus,256));
   encrypt_block(msg,encrypted,pub_key,modulus);
   printf("encrypted msg: ");
   for(int i = 0;i<ENCRYPED_BLOCK_SIZE;i++){
      printf("%02x", encrypted[i]);
   }
   printf("\n");
   decrypt_block(encrypted,recoveredtext,priv_key,modulus);
   printf("decrypted msg: ");
   for(int i = 0;i<BLOCK_SIZE;i++){
      printf("%c", recoveredtext[i]);
   }
   printf("\n");
}
