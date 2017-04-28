#include <gmp.h>
#include "protocol.h"
#ifndef socketio_header_file
#define socketio_header_file
int usage (char *progname);
int errexit (char *format, char *arg);
void write_data(void *data,int len,uint32_t socket_descriptor);
int read_data(void *data,int len,uint32_t socket_descriptor);
void close_socket(uint32_t socket_descriptor);
void send_empty_cmd(uint32_t socket_descriptor,int protocol);
void send_ack(uint32_t socket_descriptor,int protocol);
int receive_ack(uint32_t socket_descriptor);
int receive_empty_cmd(uint32_t socket_descriptor);
void send_enc_login_token(uint8_t *token,mpz_t public_key, uint32_t socket_descriptor);
void receive_enc_login_token(uint8_t *token,mpz_t public_key,mpz_t private_key, uint32_t socket_descriptor);
#endif
