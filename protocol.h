#include "crypto.h"
#include <stdint.h>
#include <gmp.h>
#ifndef protocol_header_file
#define protocol_header_file
#define REAL_MAX_DATA_SIZE 255
#define MAX_DATA_SIZE 254
#define META_DATA_SIZE 253
#define NAME_SIZE 80


#define SHARE_PUB_KEY_PROT 10 ///server shares public key with client unencrypted
#define REGISTER_PROT 11 ///client registers public key and username with server unencrypted
#define REGISTER_PROT_ACK 12
#define REGISTER_PROT_NACK 13

#define LOGIN_PROT 20
#define HANDSHAKE_PROT 21
#define LOGIN_ACK 22
#define LOGIN_NACK 23

#define MESSAGE_PROT 30
#define INTERNAL_MESSAGE_PROT 31
#define FILE_PROT 31

#define REQ_KEY_PROT 40
#define REQ_KEY_ACK 41
#define REQ_KEY_NACK 42

#define CLOSE_PROT 5

typedef struct data_packet data_packet;
struct data_packet{
   uint8_t protocol;
   uint8_t metadata[REAL_MAX_DATA_SIZE];
   uint8_t data[REAL_MAX_DATA_SIZE];
};

typedef struct metadata metadata;
struct metadata{
   uint8_t data_len;
   uint8_t meta_data[META_DATA_SIZE];
};

typedef struct msg_metadata msg_metadata;
struct msg_metadata{
   uint8_t src_name_len;
   uint8_t rcpt_name_len;
   uint8_t rcpt_name[NAME_SIZE];
   uint8_t src_name[NAME_SIZE];
};

typedef struct key_packet key_packet;
struct key_packet{
   uint8_t data[REAL_MAX_DATA_SIZE];
};

void data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data, metadata *meta,mpz_t public_key,mpz_t priv_key);
void raw_data_to_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t public_key);
void write_msg_metadata_to_data(uint8_t *data,msg_metadata *meta);
void read_msg_metadata_from_data(uint8_t *data,msg_metadata *meta);
void remove_newline(char *str,int len);
void fill_msg_metadata(msg_metadata *msg_m,char *src_name,char *rcpt_name);
void read_msg_metadata(msg_metadata *msg_m,char *src_name,char *rcpt_name);
void raw_data_to_dual_enc_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t metadata_public_key,mpz_t data_public_key);
void convert_dual_enc_packet_enc_packet(data_packet *packet,mpz_t old_metadata_public_key,mpz_t old_metadata_private_key,mpz_t new_metadata_public_key);
#endif
