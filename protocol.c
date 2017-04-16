#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include "protocol.h"
#include "crypto.h"

void raw_data_to_plaintext_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta);
void raw_data_to_enc_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t public_key);
void enc_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta,mpz_t public_key,mpz_t priv_key);
void plaintext_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta);

void write_msg_metadata_to_data(uint8_t *data,msg_metadata *meta){
   for(int i = 0;i<sizeof(metadata);i++){
      data[i] = ((uint8_t *)meta)[i];
   }
}

void read_msg_metadata_from_data(uint8_t *data,msg_metadata *meta){
   for(int i = 0;i<sizeof(metadata);i++){
      ((uint8_t *)meta)[i] = data[i];
   }
}

void data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data, metadata *meta,mpz_t *public_key,mpz_t *priv_key){
   if(packet->protocol == MESSAGE_PROT || packet->protocol == FILE_PROT){
      enc_data_packet_to_raw_data(packet,protocol,data,meta,*public_key,*priv_key);
   }else{
      plaintext_data_packet_to_raw_data(packet,protocol,data,meta);
   }
}

void raw_data_to_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t *public_key){
   if(protocol == MESSAGE_PROT || protocol == FILE_PROT){
      raw_data_to_enc_data_packet(packet,protocol,data,meta,*public_key);
   }else{
      raw_data_to_plaintext_data_packet(packet,protocol,data,meta);
   }
}

void raw_data_to_plaintext_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta){
   packet->protocol = protocol;
   for(int i = 0;i<sizeof(metadata);i++){
      packet->metadata[i] = ((uint8_t *)meta)[i];
   }
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      packet->data[i] = data[i];
   }
}

void raw_data_to_enc_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t public_key){
   uint8_t enc_data[MAX_DATA_SIZE];
   mpz_t pub_key_exp;
   mpz_init_set_ui(pub_key_exp,PUB_KEY_EXP);
   encrypt_block(data,enc_data,pub_key_exp,public_key);
   uint8_t enc_metadata[MAX_DATA_SIZE];
   encrypt_block((uint8_t *)meta,enc_metadata,pub_key_exp,public_key);
   mpz_clear(pub_key_exp);
   packet->protocol = protocol;
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      packet->data[i] = enc_data[i];
      packet->metadata[i] = enc_metadata[i];
   }
   mpz_clear(pub_key_exp);
}

void enc_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta,mpz_t public_key,mpz_t priv_key){
   *protocol = packet->protocol;
   uint8_t dec_data[MAX_DATA_SIZE];
   decrypt_block(packet->data,dec_data,priv_key,public_key);
   uint8_t dec_metadata[MAX_DATA_SIZE];
   decrypt_block(packet->metadata,dec_metadata,priv_key,public_key);
   for(int i = 0;i<sizeof(metadata);i++){
      ((uint8_t*)meta)[i] = dec_metadata[i];
   }
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      data[i] = dec_data[i];
   }
}
void plaintext_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta){
   *protocol = packet->protocol;
   for(int i = 0;i<sizeof(metadata);i++){
      ((uint8_t *)meta)[i] = packet->metadata[i];
   }
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      data[i] = packet->data[i];
   }
}
void remove_newline(char *str,int len){
   for(int i = 0;i<len;i++){
      if(str[i]=='\n')
         str[i] = '\0';
   }
}
