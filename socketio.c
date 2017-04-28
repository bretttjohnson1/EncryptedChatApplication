#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socketio.h"
#include "protocol.h"

#define ERROR 1

void send_enc_login_token(uint8_t *token,mpz_t public_key, uint32_t socket_descriptor){
   data_packet data_packt;
   metadata meta;
   meta.data_len = MAX_DATA_SIZE;
   raw_data_to_data_packet(&data_packt,HANDSHAKE_PROT,token,&meta,public_key);
   write_data(&data_packt,sizeof(data_packet),socket_descriptor);
}

void receive_enc_login_token(uint8_t *token,mpz_t public_key,mpz_t private_key, uint32_t socket_descriptor){
   data_packet data_packt;
   read_data(&data_packt,sizeof(data_packet),socket_descriptor);
   uint8_t protocol;
   metadata meta;
   data_packet_to_raw_data(&data_packt,&protocol,token,&meta,public_key,private_key);
}

int receive_ack(uint32_t socket_descriptor){
   return receive_empty_cmd(socket_descriptor);
}
int receive_empty_cmd(uint32_t socket_descriptor){
   data_packet data_packt;
   read_data(&data_packt,sizeof(data_packet),socket_descriptor);
   uint8_t protocol;
   metadata meta;
   uint8_t data[MAX_DATA_SIZE];
   data_packet_to_raw_data(&data_packt,&protocol,data,&meta,NULL,NULL);
   return protocol;
}
void send_ack(uint32_t socket_descriptor,int protocol){
   send_empty_cmd(socket_descriptor,protocol);
}
void send_empty_cmd(uint32_t socket_descriptor,int protocol){
   data_packet data_packt;
   uint8_t data[MAX_DATA_SIZE];
   metadata meta;
	meta.data_len = 0;
   fillzero(meta.meta_data,META_DATA_SIZE);
   raw_data_to_data_packet(&data_packt,protocol,data,&meta,NULL);
   write_data(&data_packt,sizeof(data_packet),socket_descriptor);
}

int usage (char *progname)
{
	fprintf (stderr,"usage: %s host port\n", progname);
	exit (ERROR);
}

int errexit (char *format, char *arg)
{
	fprintf (stderr,format,arg);
	fprintf (stderr,"\n");
	exit (ERROR);
}
void write_data(void *data,int len,uint32_t socket_descriptor){
	if (write (socket_descriptor,data,len)<= 0)
		errexit ("error writing message: %s", data);

}
int read_data(void *data,int len,uint32_t socket_descriptor){
	memset (data,0x0,len);
	int ret;
	ret = read (socket_descriptor,data,len);
	if (ret <= 0)
		printf("reading error");
   return ret;
}
void close_socket(uint32_t socket_descriptor){
	close (socket_descriptor);
}
