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

void send_pub_key_to_client(mpz_t pub_key,int socket_descriptor){
   data_packet data_packt;
   uint8_t data[MAX_DATA_SIZE];
   size_t countp;
	mpz_export(data,&countp,1,sizeof(uint8_t),1,0,pub_key);
	metadata meta;
	meta.data_len = countp;
   fillzero(meta.meta_data,META_DATA_SIZE);
   raw_data_to_data_packet(&data_packt,SHARE_PUB_KEY_PROT,data,&meta,NULL);
   write_data(&data_packt,sizeof(data_packet),socket_descriptor);
}

void rec_pub_key_from_server(mpz_t pub_key,int socket_descriptor){
   data_packet data_packt;
   read_data(&data_packt,sizeof(data_packet),socket_descriptor);
   uint8_t protocol;
   metadata meta;
   uint8_t data[MAX_DATA_SIZE];
   data_packet_to_raw_data(&data_packt,&protocol,data,&meta,NULL,NULL);
   if(protocol!=SHARE_PUB_KEY_PROT){
      errexit("ERROR: Bad PUB KEY\n","BAD PROTOCOL");
   }
   mpz_init(pub_key);
   mpz_import(pub_key,meta.data_len,1,sizeof(uint8_t),1,0,data);
}

void register_name(char* username,int len, mpz_t pub_key,int socket_descriptor){
   data_packet data_packt;
	uint8_t data[MAX_DATA_SIZE];
	size_t countp;
	mpz_export(data,&countp,1,sizeof(uint8_t),1,0,pub_key);
	metadata meta;
	meta.data_len = countp;
	msg_metadata namedata;
	namedata.name_len = len;
	for(int i = 0; i<len; i++) {
		namedata.rcpt_name[i] = username[i];
	}
   write_msg_metadata_to_data(meta.meta_data,&namedata);
   raw_data_to_data_packet(&data_packt,REGISTER_PROT,data,&meta,NULL);
   write_data(&data_packt,sizeof(data_packet),socket_descriptor);
}
void read_register_name(data_packet *data_packt,char* username,int *len, mpz_t pub_key){
   metadata meta;
   uint8_t protocol;
   uint8_t data[MAX_DATA_SIZE];
   data_packet_to_raw_data(data_packt,&protocol,data,&meta,NULL,NULL);
   msg_metadata namedata;
   read_msg_metadata_from_data(meta.meta_data,&namedata);
   *len = namedata.name_len;
	for(int i = 0; i<namedata.name_len; i++) {
		username[i] = namedata.rcpt_name[i];
	}
   mpz_init(pub_key);
   mpz_import(pub_key,MAX_DATA_SIZE,1,sizeof(uint8_t),1,0,data);
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
void write_data(void *data,int len,int socket_descriptor){
	if (write (socket_descriptor,data,len)<= 0)
		errexit ("error writing message: %s", data);

}
int read_data(void *data,int len,int socket_descriptor){
	memset (data,0x0,len);
	int ret;
	ret = read (socket_descriptor,data,len);
	if (ret <= 0)
		errexit ("reading error",NULL);
   return ret;
}
void close_socket(int socket_descriptor){
	close (socket_descriptor);
}
