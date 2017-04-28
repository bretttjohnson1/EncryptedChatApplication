#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <stdlib.h>
#include "protocol.h"
#include "crypto.h"
#include "bool.h"

void raw_data_to_plaintext_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta);
void raw_data_to_enc_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t public_key);
void enc_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta,mpz_t public_key,mpz_t priv_key);
void plaintext_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta);
bool is_encrypted_prot(int protocol);

void fill_msg_metadata(msg_metadata *msg_m,char *src_name,char *rcpt_name){
   msg_m->src_name_len = strlen(src_name)+1;
   for(uint8_t i = 0;i<msg_m->src_name_len;i++){
      msg_m->src_name[i] = src_name[i];
   }
   msg_m->rcpt_name_len = strlen(rcpt_name)+1;
   for(uint8_t i = 0;i<msg_m->rcpt_name_len;i++){
      msg_m->rcpt_name[i] = rcpt_name[i];
   }
}

void read_msg_metadata(msg_metadata *msg_m,char *src_name,char *rcpt_name){
   for(uint8_t i = 0;i<msg_m->src_name_len;i++){
      src_name[i] = msg_m->src_name[i];
   }
   for(uint8_t i = 0;i<msg_m->rcpt_name_len;i++){
      rcpt_name[i] = msg_m->rcpt_name[i];
   }
}

void write_msg_metadata_to_data(uint8_t *data,msg_metadata *meta){
   for(int i = 0;i<sizeof(msg_metadata);i++){
      data[i] = ((uint8_t *)meta)[i];
   }
}

void read_msg_metadata_from_data(uint8_t *data,msg_metadata *meta){
   for(int i = 0;i<sizeof(msg_metadata);i++){
      ((uint8_t *)meta)[i] = data[i];
   }
}

void data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data, metadata *meta,mpz_t public_key,mpz_t priv_key){
   if(is_encrypted_prot(packet->protocol)){
      enc_data_packet_to_raw_data(packet,protocol,data,meta,public_key,priv_key);
   }else{
      plaintext_data_packet_to_raw_data(packet,protocol,data,meta);
   }
}

void raw_data_to_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t public_key){
   if(is_encrypted_prot(protocol)){
      raw_data_to_enc_data_packet(packet,protocol,data,meta,public_key);
   }else{
      raw_data_to_plaintext_data_packet(packet,protocol,data,meta);
   }
}
bool is_encrypted_prot(int protocol){
   return protocol == MESSAGE_PROT || protocol == FILE_PROT || protocol == HANDSHAKE_PROT;
}

void raw_data_to_plaintext_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta){
   packet->protocol = protocol;
   for(int i = 0;i<sizeof(metadata);i++){
      packet->metadata[i] = ((uint8_t *)meta)[i];
   }
   for(int i = 0;i<REAL_MAX_DATA_SIZE;i++){
      packet->data[i] = data[i];
   }
}

void raw_data_to_enc_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t public_key){
   uint8_t enc_data[REAL_MAX_DATA_SIZE];
   mpz_t pub_key_exp;
   mpz_init_set_ui(pub_key_exp,PUB_KEY_EXP);
   encrypt_block(data,enc_data,pub_key_exp,public_key);
   uint8_t enc_metadata[REAL_MAX_DATA_SIZE];
   encrypt_block((uint8_t *)meta,enc_metadata,pub_key_exp,public_key);
   packet->protocol = protocol;
   for(int i = 0;i<REAL_MAX_DATA_SIZE;i++){
      packet->data[i] = enc_data[i];
      packet->metadata[i] = enc_metadata[i];
   }
   mpz_clear(pub_key_exp);
}

void enc_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta,mpz_t public_key,mpz_t priv_key){
   *protocol = packet->protocol;
   uint8_t dec_data[REAL_MAX_DATA_SIZE];
   decrypt_block(packet->data,dec_data,priv_key,public_key);
   uint8_t dec_metadata[REAL_MAX_DATA_SIZE];
   decrypt_block(packet->metadata,dec_metadata,priv_key,public_key);
   for(int i = 0;i<sizeof(metadata);i++){
      ((uint8_t*)meta)[i] = dec_metadata[i];
   }
   for(int i = 0;i<MAX_DATA_SIZE;i++){
      data[i] = dec_data[i];
   }
}

void raw_data_to_dual_enc_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t metadata_public_key,mpz_t data_public_key){
   uint8_t enc_data[REAL_MAX_DATA_SIZE];
   mpz_t pub_key_exp;
   mpz_init_set_ui(pub_key_exp,PUB_KEY_EXP);
   encrypt_block(data,enc_data,pub_key_exp,data_public_key);
   uint8_t enc_metadata[REAL_MAX_DATA_SIZE];
   encrypt_block((uint8_t *)meta,enc_metadata,pub_key_exp,metadata_public_key);
   packet->protocol = protocol;
   for(int i = 0;i<REAL_MAX_DATA_SIZE;i++){
      packet->data[i] = enc_data[i];
      packet->metadata[i] = enc_metadata[i];
   }
   mpz_clear(pub_key_exp);
}

void convert_dual_enc_packet_enc_packet(data_packet *packet,mpz_t old_metadata_public_key,mpz_t old_metadata_private_key,mpz_t new_metadata_public_key){
   mpz_t pub_key_exp;
   mpz_init_set_ui(pub_key_exp,PUB_KEY_EXP);
   uint8_t dec_metadata[REAL_MAX_DATA_SIZE];
   decrypt_block(packet->metadata,dec_metadata,old_metadata_private_key,old_metadata_public_key);
   encrypt_block(dec_metadata, packet->metadata, pub_key_exp, new_metadata_public_key);
}

void plaintext_data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data,metadata *meta){
   *protocol = packet->protocol;
   for(int i = 0;i<sizeof(metadata);i++){
      ((uint8_t *)meta)[i] = packet->metadata[i];
   }
   for(int i = 0;i<REAL_MAX_DATA_SIZE;i++){
      data[i] = packet->data[i];
   }
}
void remove_newline(char *str,int len){
   for(int i = 0;i<len;i++){
      if(str[i]=='\n')
         str[i] = '\0';
   }
}
