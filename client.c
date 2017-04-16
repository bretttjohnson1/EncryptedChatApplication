
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socketio.h"
#include <string.h>
#include "bool.h"

#define PROTOCOL "tcp"
int setup (char * hoststr, char *portstr);

const int max_cmd_size = 256;
void command_loop(int socket_descriptor);
int main(int argc, char **argv){
   opterr = 0;
   int opt = 0;
   char *portstr;
   char *hoststr;
   int numargs = 0;
	while((opt = getopt(argc,argv,"p:h:"))!=-1) {
		switch (opt) {
		case 'p':
         numargs++;
         portstr = optarg;
			break;
      case 'h':
         numargs++;
         hoststr = optarg;
         break;
		default:
			printf("ERROR: invalid option\n");
			return 1;
		}
	}
   if(numargs!=2){
      printf("ERROR: MISSING ARGS\n");
      exit(1);
   }
   int socket_descriptor = setup(hoststr,portstr);
   if(!has_generated_key()) {
      generate_and_store_keys();
   }
   mpz_t public_key;
   rec_pub_key_from_server(public_key,socket_descriptor);
   command_loop(socket_descriptor);
}

void command_loop(int socket_descriptor){
   bool exit = false;
   while(!exit){
      char cmd[max_cmd_size];
      fgets(cmd,max_cmd_size,stdin);
      char *command = strtok(cmd," \0\n");
      if(strcasecmp(command,"LOGIN")==0){
         char *uname = strtok(NULL," ");
         mpz_t public_key;
         read_local_public_key_from_file(public_key);
         gmp_printf("%Z02x\n",public_key );
         printf("%s\n",uname );
         register_name(uname,strlen(uname),public_key,socket_descriptor);
         mpz_clear(public_key);
      }
      if(strcasecmp(command,"genkeys\n")==0 || strcasecmp(command,"genkeys")==0){
         printf("Are you sure? This will destroy any login info (type y/n): ");
         fgets(cmd,max_cmd_size,stdin);
         if(strcasecmp(cmd,"y\n")==0){
            generate_and_store_keys();
            printf("New keys have been generated\n");
         }else{
            printf("Aborted\n");
         }
      }
   }
}
int setup (char * hoststr, char *portstr)
{
    struct sockaddr_in sin;
    struct hostent *hinfo;
    struct protoent *protoinfo;
    int sd;
    /* lookup the hostname */
    hinfo = gethostbyname (hoststr);
    if (hinfo == NULL)
        errexit ("cannot find name: %s", hoststr);

    /* set endpoint information */
    memset ((char *)&sin, 0x0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons (atoi (portstr));
    memcpy ((char *)&sin.sin_addr,hinfo->h_addr,hinfo->h_length);

    if ((protoinfo = getprotobyname (PROTOCOL)) == NULL)
        errexit ("cannot find protocol information for %s", PROTOCOL);

    /* allocate a socket */
    /*   would be SOCK_DGRAM for UDP */
    sd = socket(PF_INET, SOCK_STREAM, protoinfo->p_proto);
    if (sd < 0)
        errexit("cannot create socket",NULL);

    /* connect the socket */
    if (connect (sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        errexit ("cannot connect", NULL);

   return sd;
}
