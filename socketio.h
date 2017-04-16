#include <gmp.h>
#include "protocol.h"
#ifndef socketio_header_file
#define socketio_header_file
int usage (char *progname);
int errexit (char *format, char *arg);
void write_data(void *data,int len,int socket_descriptor);
int read_data(void *data,int len,int socket_descriptor);
void close_socket(int socket_descriptor);
void send_pub_key_to_client(mpz_t pub_key,int socket_descriptor);
void rec_pub_key_from_server(mpz_t pub_key,int socket_descriptor);
void register_name(char* username,int len, mpz_t pub_key,int socket_descriptor);
void read_register_name(data_packet *data_packt,char* username,int *len, mpz_t pub_key);

#endif
