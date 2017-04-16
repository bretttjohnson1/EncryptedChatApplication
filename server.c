
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socketio.h"
#include "crypto.h"
#include "bool.h"
#include <getopt.h>

#define QLEN 1
#define PROTOCOL "tcp"
const int portlen = 12;
int setup (char *portstr);
void response_loop(int socket_descriptor);
void handle_register(data_packet *data_packt);

int main(int argc,char **argv){
	opterr = 0;
	int opt = 0;
	char *portstr;
	int numargs = 0;
	while((opt = getopt(argc,argv,"p:"))!=-1) {
		switch (opt) {
		case 'p':
			numargs++;
			portstr = optarg;
			break;
		default:
			numargs++;
			printf("ERROR: invalid option\n");
			return 1;
		}
	}
	if(numargs!=1) {
		printf("ERROR: MISSING ARGS\n");
		exit(1);
	}

	int socket_descriptor = setup(portstr);
	//if(!has_generated_key()) {
   generate_and_store_keys(); /// TODO add cli
	//}
   mpz_t public_key;
   read_local_public_key_from_file(public_key);
	send_pub_key_to_client(public_key,socket_descriptor);
   mpz_clear(public_key);
	response_loop(socket_descriptor);
}

void response_loop(int socket_descriptor){
	bool exit  = false;
	while(!exit) {
		data_packet packet;
		int ret = read_data(&packet,sizeof(data_packet),socket_descriptor);
      printf("return: %d\n", ret);
      if(ret==0)
         exit = true;
		uint8_t protocol = packet.protocol;
		printf("PACKET READ: protocol %d\n",protocol);
		switch (protocol) {
		case REGISTER_PROT:
			handle_register(&packet);
			break;
		}
	}
}

void handle_register(data_packet *data_packt){
	char username[NAME_SIZE];
	int len;
	mpz_t public_key;
	read_register_name(data_packt,username,&len,public_key);
	gmp_printf("recieved register request from %s\n",username);
   remove_newline(username,NAME_SIZE);
   char *keyfilename =strcat(username,"_pub.key");
   if(access(keyfilename, F_OK)!=-1){
      printf("user already registered\n");////////////////////////////////////send nack
   }else{
      printf("user %s has been registered\n",username);
      write_key_to_file(public_key,keyfilename);
   }
	mpz_clear(public_key);
}


int setup (char *portstr)
{
	struct sockaddr_in sin;
	struct sockaddr addr;
	struct protoent *protoinfo;
	unsigned int addrlen;
	int sd, sd2;

	/* determine protocol */
	if ((protoinfo = getprotobyname (PROTOCOL)) == NULL)
		errexit ("cannot find protocol information for %s", PROTOCOL);

	/* setup endpoint info */
	memset ((char *)&sin,0x0,sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons ((u_short) atoi (portstr));

	/* allocate a socket */
	/*   would be SOCK_DGRAM for UDP */
	sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
	if (sd < 0)
		errexit("cannot create socket", NULL);

	/* bind the socket */
	if (bind (sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		errexit ("cannot bind to port %s", portstr);

	/* listen for incoming connections */
	if (listen (sd, QLEN) < 0)
		errexit ("cannot listen on port %s\n", portstr);

	/* accept a connection */
	sd2 = accept (sd,&addr,&addrlen);
	if (sd2 < 0)
		errexit ("error accepting connection", NULL);

	return sd2;

}
