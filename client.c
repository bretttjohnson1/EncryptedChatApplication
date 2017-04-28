
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
#include "protocol.h"
#include <string.h>
#include "bool.h"
#include <pthread.h>
#include <errno.h>

#define PROTOCOL "tcp"
int setup (char * hoststr, char *portstr);

const int max_cmd_size = 256;
void command_loop(int socket_descriptor,int mail_socket_descriptor,mpz_t server_public_key);
void rec_pub_key_from_server(mpz_t pub_key,int socket_descriptor);
void send_login_request(char *uname,int uname_len,int socket_descriptor);
void register_name(char* username,int len, mpz_t pub_key,int socket_descriptor);
void handle_login(char *uname,mpz_t server_public_key, uint32_t socket_descriptor);
void *mail_handler(void *mail_socket_descriptor_pointer);
bool get_public_key_from_name(char *name,mpz_t public_key,uint32_t socket_descriptor);
void send_msg(char* username,char *dest,char *msg,uint32_t socket_descriptor,mpz_t server_public_key);
void handle_internal_msg(data_packet *packet);
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
	if(numargs!=2) {
		printf("ERROR: MISSING ARGS\n");
		exit(1);
	}
	if(!has_generated_key()) {
		generate_and_store_keys();
	}
	uint32_t currentport;
	uint32_t port_sock_desc = setup(hoststr,portstr);
	read_data(&currentport, sizeof(uint32_t), port_sock_desc);
	close(port_sock_desc);

	char mainportstr[NAME_SIZE];
	char mailportstr[NAME_SIZE];
	sprintf(mainportstr, "%d", currentport);
	sprintf(mailportstr, "%d", currentport+1);
	uint32_t socket_descriptor = setup(hoststr,mainportstr);
	uint32_t mail_socket_descriptor = setup(hoststr,mailportstr);
	mpz_t server_public_key;
	rec_pub_key_from_server(server_public_key,socket_descriptor);
   printf("Welcome to Brett's encrypted chat server\nType /help for a list of commands\n");

	command_loop(socket_descriptor,mail_socket_descriptor, server_public_key);
}

void command_loop(int socket_descriptor,int mail_socket_descriptor,mpz_t server_public_key){
	bool exit = false;
	bool logged_in = false;
	char loggedinusername[NAME_SIZE];
	pthread_t mail_thread_tid;
	pthread_attr_t mail_thread_attr;
	while(!exit) {
		char cmd[max_cmd_size];
		fgets(cmd,max_cmd_size,stdin);
		char original_cmd[max_cmd_size];
		strcpy(original_cmd, cmd);
		char *command = strtok(cmd," \0\n");
		remove_newline(command,strlen(command));
		if(strcasecmp(command,"/register")==0) {
			char *uname = strtok(NULL," ");
			if(uname != NULL) {
				mpz_t public_key;
				read_local_public_key_from_file(public_key);
				register_name(uname,strlen(uname),public_key,socket_descriptor);
				mpz_clear(public_key);
				int ack = receive_ack(socket_descriptor);
				remove_newline(uname,strlen(uname));
				if(ack == REGISTER_PROT_ACK) {
					printf("User %s registered\n",uname);
				}
				if(ack == REGISTER_PROT_NACK) {
					printf("User %s already registered\n",uname);
				}
			}else{
				printf("Username required\n");
			}
		}else if(strcasecmp(command,"/login")==0) {
			char *uname = strtok(NULL," ");
			if(uname !=NULL) {
				char unamecpy[strlen(uname)+1];
				strcpy(unamecpy, uname);
				remove_newline(unamecpy, strlen(unamecpy));
				remove_newline(uname, strlen(uname));
				send_login_request(uname, strlen(uname), socket_descriptor);
				int loggedinack = receive_ack(socket_descriptor);
				if(loggedinack == LOGIN_ACK) {
					int existsack = receive_ack(socket_descriptor);
					if(existsack == LOGIN_ACK) {

						uint8_t token[ENCRYPED_BLOCK_SIZE];
						mpz_t public_key;
						read_local_public_key_from_file(public_key);
						mpz_t private_key;
						read_local_private_key_from_file(private_key);
						receive_enc_login_token(token, public_key, private_key, socket_descriptor);
						send_enc_login_token(token, server_public_key, socket_descriptor);
						int ack = receive_ack(socket_descriptor);
						if(ack == LOGIN_ACK) {
							printf("Successfuly Logged In as %s\n",unamecpy);
							strcpy(loggedinusername,unamecpy);
							logged_in = true;
							pthread_attr_init(&mail_thread_attr);
							pthread_create(&mail_thread_tid, &mail_thread_attr, mail_handler, &mail_socket_descriptor);
						}else if(ack == LOGIN_NACK) {
							printf("Failed to Login as %s\n",unamecpy);
						}else{
							errexit("BAD ACKNO %s", "badack");
						}
						mpz_clear(public_key);
						mpz_clear(private_key);

					}else{
						printf("Username not found\n");
					}
				}else{
					printf("Already Logged In\n");
				}
			}else{
				printf("Username required\n");
			}

		}else if(strcasecmp(command,"/msg")==0) {
			if(logged_in) {
				char *rcpt = strtok(NULL," ");
				if(rcpt!=NULL) {
					char rcpt_cpy[strlen(rcpt)+1];
					strcpy(rcpt_cpy, rcpt);
					int pos = strlen(command)+1+strlen(rcpt)+1;
					char *msg = original_cmd+pos;
					if(strlen(original_cmd)-pos>0) {
						remove_newline(rcpt_cpy, strlen(rcpt_cpy));
						remove_newline(rcpt, strlen(rcpt));
						send_msg(loggedinusername, rcpt_cpy, msg, socket_descriptor, server_public_key);
					}else{
						printf("Need to include message\n");
					}
				}else{
					printf("Need to include recipient\n");
				}
			}else{
				printf("Need to log in before sending messages\n");
			}
		}else if(strcasecmp(command,"/mall")==0) {
			if(logged_in) {
            send_empty_cmd(socket_descriptor, LIST_ONLINE_PROT);
   			data_packet read_packet;
   			read_data(&read_packet, sizeof(data_packet), socket_descriptor);
   			remove_newline((char *)read_packet.data, MAX_DATA_SIZE);
   			char rcp_data[MAX_DATA_SIZE];
            strcpy(rcp_data, (char *)read_packet.data);

				char *rcpt = strtok(rcp_data," ");
				while(rcpt!=NULL) {
					char rcpt_cpy[strlen(rcpt)+1];
					strcpy(rcpt_cpy, rcpt);
					int pos = strlen(command)+1;
					char *msg = original_cmd+pos;
					if(strlen(original_cmd)-pos>0) {
						remove_newline(rcpt_cpy, strlen(rcpt_cpy));
						remove_newline(rcpt, strlen(rcpt));
						send_msg(loggedinusername, rcpt_cpy, msg, socket_descriptor, server_public_key);
					}else{
						printf("Need to include message\n");
                  break;
					}
               rcpt = strtok(NULL," ");
				}
			}else{
				printf("Need to log in before sending messages\n");
			}
		}  else if(strcasecmp(command,"/exit")==0) {
			send_ack(socket_descriptor,CLOSE_PROT);
			return;
		}else if(strcasecmp(command,"/genkeys")==0) {
			printf("Are you sure? This will destroy any login info (type y/n): ");
			fgets(cmd,max_cmd_size,stdin);
			remove_newline(cmd,strlen(cmd));
			if(strcasecmp(cmd,"y")==0) {
				generate_and_store_keys();
				printf("New keys have been generated\n");
			}else{
				printf("Aborted\n");
			}
		}else if(strcasecmp(command,"/listonline")==0) {
			send_empty_cmd(socket_descriptor, LIST_ONLINE_PROT);
			data_packet read_packet;
			read_data(&read_packet, sizeof(data_packet), socket_descriptor);
			remove_newline((char *)read_packet.data, MAX_DATA_SIZE);
			printf("Currently Online: %s\n",read_packet.data);
		}else if(strcasecmp(command,"/help")==0){
         printf("Welcome to Brett's encrypted chat server\n");
         printf("If you are not registered, type /register [username] to add yourself to the server\n");
         printf("Once you have registered,you can use /login [username to log in at any time under the same username\n");
         printf("If you wish to register a new username, type /genkeys and then register another username\nBe careful, once you generate new keys, the old user is gone forever\n");
         printf("To see who is online, type /listonline\n");
         printf("To message an online user, type /msg [rcpt] [message]\n");
         printf("To message all online users, type /malll [message]\n");
         printf("To exit, type /exit\n");

      }else{
			printf("Invalid cmd type help for list\n");
		}
	}
	if(logged_in) {
		pthread_join(mail_thread_tid, NULL);
	}
}

void send_msg(char* username,char *dest,char *msg,uint32_t socket_descriptor,mpz_t server_public_key){
	uint8_t data[MAX_DATA_SIZE];
	for(int i = 0; i<strlen(msg)+1; i++) {
		data[i] = msg[i];
	}
	mpz_t public_key;
	bool read_key = get_public_key_from_name(dest, public_key, socket_descriptor);
	if(read_key) {
		data_packet packet;
		msg_metadata msg_m;
		fill_msg_metadata(&msg_m, username, dest);
		metadata meta;
		meta.data_len = strlen(msg)+1;

		write_msg_metadata_to_data(meta.meta_data, &msg_m);
		raw_data_to_dual_enc_packet(&packet, MESSAGE_PROT, data, &meta,server_public_key,public_key);
		write_data(&packet, sizeof(data_packet), socket_descriptor);
		mpz_clear(public_key);
	}else{
		printf("Destination name not found\n");
	}
}

bool get_public_key_from_name(char *name,mpz_t public_key,uint32_t socket_descriptor){
	mpz_init(public_key);
	data_packet packet;
	uint8_t data[REAL_MAX_DATA_SIZE];
	fillzero(data,REAL_MAX_DATA_SIZE);
	msg_metadata msg_m;
	char rcpt_name[NAME_SIZE];
	fill_msg_metadata(&msg_m, name, rcpt_name);
	metadata meta;
	meta.data_len = MAX_DATA_SIZE;

	write_msg_metadata_to_data(meta.meta_data, &msg_m);
	raw_data_to_data_packet(&packet, REQ_KEY_PROT, data, &meta, NULL);
	write_data(&packet, sizeof(data_packet), socket_descriptor);
	int keyack = receive_ack(socket_descriptor);
	if(keyack == REQ_KEY_ACK) {
		data_packet read_packet;
		metadata newmeta;
		uint8_t protocol;
		int ret = read_data(&read_packet, sizeof(data_packet), socket_descriptor);
		if(ret<=0) {
			//errstuff
		}
		uint8_t newdata[MAX_DATA_SIZE];
		data_packet_to_raw_data(&read_packet,&protocol, newdata, &newmeta, NULL, NULL);
		mpz_import(public_key,newmeta.data_len,1,sizeof(uint8_t),1,0,newdata);
		return true;
	}else{
		return false;
	}
}

void *mail_handler(void *mail_socket_descriptor_pointer){
	int mail_socket_descriptor = *((int *)mail_socket_descriptor_pointer);
	bool exit = false;
	while(!exit) {
		data_packet packet;
		int ret = read_data(&packet,sizeof(data_packet),mail_socket_descriptor);
		if(ret==0)
			exit = true;
		uint8_t protocol = packet.protocol;
		switch (protocol) {
		case INTERNAL_MESSAGE_PROT:
			handle_internal_msg(&packet);
			break;
		default:
			break;
		}
	}
	return NULL;
}

void handle_internal_msg(data_packet *packet){
	uint8_t encmsg[REAL_MAX_DATA_SIZE];
	for(int i = 0; i<REAL_MAX_DATA_SIZE; i++) {
		encmsg[i] = packet->data[i];
	}
	mpz_t public_key;
	read_local_public_key_from_file(public_key);
	mpz_t private_key;
	read_local_private_key_from_file(private_key);
	uint8_t protocol;
	uint8_t data[MAX_DATA_SIZE];
	metadata meta;
	data_packet_to_raw_data(packet, &protocol, data, &meta,public_key, private_key);
	msg_metadata msg_m;
	read_msg_metadata_from_data(meta.meta_data, &msg_m);
	char src_name[NAME_SIZE];
	char rcpt_name[NAME_SIZE];
	read_msg_metadata(&msg_m, src_name, rcpt_name);

	printf("(%s): %s",src_name,data);
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
	int ret = connect (sd, (struct sockaddr *)&sin, sizeof(sin));
	int count = 0;
	if(ret < 0 ) {
		while (ret < 0) {
			sleep(1);
			ret = connect (sd, (struct sockaddr *)&sin, sizeof(sin));
			printf("Failed to connect trying again\n");
			count++;
			if(count>10)
				errexit("cannot connect: %s", strerror(errno));
		}
	}
	return sd;
}

void rec_pub_key_from_server(mpz_t pub_key,int socket_descriptor){
	data_packet data_packt;
	read_data(&data_packt,sizeof(data_packet),socket_descriptor);
	uint8_t protocol;
	metadata meta;
	uint8_t data[MAX_DATA_SIZE];
	data_packet_to_raw_data(&data_packt,&protocol,data,&meta,NULL,NULL);
	if(protocol!=SHARE_PUB_KEY_PROT) {
		errexit("ERROR: Bad PUB KEY\n","BAD PROTOCOL");
	}
	mpz_init(pub_key);
	mpz_import(pub_key,meta.data_len,1,sizeof(uint8_t),1,0,data);
}

void send_login_request(char *uname,int uname_len,int socket_descriptor){
	data_packet data_packt;
	metadata meta;
	uint8_t data[MAX_DATA_SIZE];
	meta.data_len = MAX_DATA_SIZE;
	msg_metadata msg_m;
	/*msg_m.src_name_len = uname_len;
	   for(int i =0;i<uname_len && i<NAME_SIZE;i++){
	   msg_m.rcpt_name[i] = uname[i];
	   }*/
	char rcpt_name[NAME_SIZE];
	fill_msg_metadata(&msg_m, uname,rcpt_name);

	write_msg_metadata_to_data(meta.meta_data, &msg_m);
	raw_data_to_data_packet(&data_packt,LOGIN_PROT,data,&meta,NULL);
	write_data(&data_packt,sizeof(data_packet),socket_descriptor);
}

void register_name(char* username,int len, mpz_t pub_key,int socket_descriptor){
	data_packet data_packt;
	uint8_t data[MAX_DATA_SIZE];
	size_t countp;
	mpz_export(data,&countp,1,sizeof(uint8_t),1,0,pub_key);
	metadata meta;
	meta.data_len = countp;
	msg_metadata namedata;
	namedata.src_name_len = len;
	for(int i = 0; i<len; i++) {
		namedata.src_name[i] = username[i];
	}
	write_msg_metadata_to_data(meta.meta_data,&namedata);
	raw_data_to_data_packet(&data_packt,REGISTER_PROT,data,&meta,NULL);
	write_data(&data_packt,sizeof(data_packet),socket_descriptor);
}
