#include "crypto.h"
#include <stdint.h>
#include <gmp.h>
#ifndef protocol_header_file
#define protocol_header_file
#define MAX_DATA_SIZE 255
#define META_DATA_SIZE 253
#define MAX
#define NAME_SIZE 20


#define SHARE_PUB_KEY_PROT 10 ///server shares public key with client unencrypted
#define REGISTER_PROT 11 ///client registers public key and username with server unencrypted
#define REGISTER_PROT_ACK 12
#define REGISTER_PROT_NACK 13

#define LOGIN_PROT 20
#define HANDSHAKE_PROT 21

#define MESSAGE_PROT 30
#define FILE_PROT 31

#define CLOSE_PROT 5

typedef struct data_packet data_packet;
struct data_packet{
   uint8_t protocol;
   uint8_t metadata[MAX_DATA_SIZE];
   uint8_t data[MAX_DATA_SIZE];
};

typedef struct metadata metadata;
struct metadata{
   uint8_t data_len;
   uint8_t meta_data[META_DATA_SIZE];
};

typedef struct msg_metadata msg_metadata;
struct msg_metadata{
   uint8_t name_len;
   uint8_t rcpt_name[NAME_SIZE];
};

typedef struct key_packet key_packet;
struct key_packet{
   uint8_t data[MAX_DATA_SIZE];
};

void data_packet_to_raw_data(data_packet *packet,uint8_t *protocol,uint8_t *data, metadata *meta,mpz_t *public_key,mpz_t *priv_key);
void raw_data_to_data_packet(data_packet *packet,uint8_t protocol,uint8_t *data,metadata *meta,mpz_t *public_key);
void write_msg_metadata_to_data(uint8_t *data,msg_metadata *meta);
void read_msg_metadata_from_data(uint8_t *data,msg_metadata *meta);
void remove_newline(char *str,int len);
#endif
