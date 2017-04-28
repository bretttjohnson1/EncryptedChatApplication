
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
#include <pthread.h>
#include <semaphore.h>
#include "hashmap.h"

#define QLEN 1
#define PROTOCOL "tcp"
const int portlen = 12;
int setup (char *portstr);
void *thread_response_loop(void *socket_descriptor);
void response_loop(uint32_t socket_descriptor,uint32_t mail_socket_descriptor);
void handle_register(data_packet *data_packt,uint32_t socket_descriptor);
void send_pub_key_to_client(mpz_t pub_key,uint32_t socket_descriptor);
void read_register_name(data_packet *data_packt,char* username,int *len, mpz_t pub_key);
bool handle_login(data_packet *data_packet,uint32_t socket_descriptor,uint32_t mail_socket_descriptor);
void handle_msg(data_packet *packet,uint32_t mail_socket_descriptor);
void send_internal_msg(data_packet *packet,uint32_t mail_socket_descriptor);
void handle_req_key(data_packet packet,uint32_t socket_descriptor);

sem_t *socket_write_sem;
sem_t *socket_map_sem;
hashmap *sem_map;
hashmap *socket_map;
int init_len_hashmap = 40;

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
	//if(!has_generated_key()) {
	//}

	generate_and_store_keys(); /// TODO add cli

	socket_map_sem = malloc(sizeof(sem_t));
	if(socket_map_sem == NULL) {
		errexit("Not Enough memory for socket_map_sem", "");
	}
	sem_init(socket_map_sem, 0, 1);

	sem_map = hash_setup(init_len_hashmap);
	socket_map = hash_setup(init_len_hashmap);
	if(sem_map == NULL ||socket_map == NULL) {
		errexit("Not Enough memory for hashmap", "");
	}
	uint32_t currentport= atoi(portstr)+1;
	while(1) {
		//send the connection ports
		printf("Setting Up At:%s\n",portstr);
		uint32_t port_sock_desc = setup(portstr);
		write_data(&currentport, sizeof(uint32_t), port_sock_desc);
		close(port_sock_desc);

		pthread_t tid;
		pthread_attr_t attr;
		char tmpportstr[NAME_SIZE];
		sprintf(tmpportstr, "%d", currentport);
		uint32_t socket_descriptor = setup(tmpportstr);
		printf("Setup Once\n");
		mpz_t public_key;
		read_local_public_key_from_file(public_key);
		send_pub_key_to_client(public_key,socket_descriptor);
		mpz_clear(public_key);
		sprintf(tmpportstr, "%d",currentport+1);
		uint32_t mail_socket_descriptor = setup(tmpportstr);
		currentport+=2;
		printf("Setup Twice\n");
		pthread_attr_init(&attr);
		uint32_t socket_descriptors[] = {socket_descriptor,mail_socket_descriptor};
		pthread_create(&tid, &attr, thread_response_loop, &socket_descriptors);
	}

}

void *thread_response_loop(void *sd){
	uint32_t *socket_descriptor = sd;
	response_loop(socket_descriptor[0],socket_descriptor[1]);
	return NULL;
}
void response_loop(uint32_t socket_descriptor,uint32_t mail_socket_descriptor){
	bool exit  = false;
	bool logged_in = false;
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
			handle_register(&packet,socket_descriptor);
			break;
		case LOGIN_PROT:
			if(!logged_in) {
				send_ack(socket_descriptor, LOGIN_ACK);
				logged_in = handle_login(&packet,socket_descriptor,mail_socket_descriptor);
			}else{
				send_ack(socket_descriptor, LOGIN_NACK);
			}
			break;
		case MESSAGE_PROT:
			handle_msg(&packet,mail_socket_descriptor);
			break;
		case REQ_KEY_PROT:;
			handle_req_key(packet,socket_descriptor);
			break;
		case CLOSE_PROT:
			exit = true;
			break;
		}
	}
}

void handle_req_key(data_packet packet,uint32_t socket_descriptor){
	uint8_t proto;
	uint8_t data[MAX_DATA_SIZE];
	metadata meta;
	data_packet_to_raw_data(&packet, &proto,data, &meta,NULL,NULL);
	msg_metadata msg_m;
	read_msg_metadata_from_data(meta.meta_data, &msg_m);
	char src_name[NAME_SIZE];
	char rcpt_name[NAME_SIZE];
	read_msg_metadata(&msg_m, src_name, rcpt_name);
	strcat((char *)src_name,"_pub.key");
	mpz_t public_key;
	bool key_exists = read_key_from_file(public_key, src_name);
	if(key_exists) {
      send_ack(socket_descriptor, REQ_KEY_ACK);
		uint8_t newdata[MAX_DATA_SIZE];
		size_t countp;
		mpz_export(newdata,&countp,1,sizeof(uint8_t),1,0,public_key);
		data_packet newdatapacket;
		metadata newmeta;
		newmeta.data_len = countp;
		raw_data_to_data_packet(&newdatapacket, REQ_KEY_ACK, newdata, &newmeta, NULL);
		write_data(&newdatapacket, sizeof(data_packet), socket_descriptor);
	}else{
		send_ack(socket_descriptor, REQ_KEY_NACK);
	}
}

void handle_msg(data_packet *packet,uint32_t mail_socket_descriptor){
	msg_metadata msg_m;
	uint8_t data[MAX_DATA_SIZE];
	metadata m;
	uint8_t protocol;
	mpz_t public_key;
	read_local_public_key_from_file(public_key);
	mpz_t private_key;
	read_local_private_key_from_file(private_key);
	data_packet_to_raw_data(packet, &protocol, data, &m, public_key,private_key);

	read_msg_metadata_from_data(m.meta_data, &msg_m);
	uint8_t uname[NAME_SIZE];
	uint8_t rcpt_name[NAME_SIZE];
	read_msg_metadata(&msg_m, (char *)uname, (char *)rcpt_name);
	strcat((char *)uname,"_pub.key");
	char keyfilename[strlen((char *)uname)+1];
	for(int i = 0; i<strlen((char *)uname); i++) {
		keyfilename[i] = uname[i];
	}
	keyfilename[strlen((char *)uname)] = '\0';

	mpz_t user_public_key;
	read_key_from_file(user_public_key, keyfilename);
	convert_dual_enc_packet_enc_packet(packet, public_key, private_key, user_public_key);
	uint32_t *sockdesc = hash_get(*socket_map, keyfilename, strlen(keyfilename));
	if(sockdesc != NULL) {
		printf("Found user %s\n",keyfilename);
	}else{
		printf("Err No user found\n");
		return;
	}
	send_internal_msg(packet,*sockdesc);

}

void send_internal_msg(data_packet *packet,uint32_t mail_socket_descriptor){
	packet->protocol = INTERNAL_MESSAGE_PROT;
	write_data(packet, sizeof(data_packet), mail_socket_descriptor);
}

bool handle_login(data_packet *data_packet,uint32_t socket_descriptor,uint32_t mail_socket_descriptor){
	bool logged_in = false;
	msg_metadata msg_m;
	uint8_t data[MAX_DATA_SIZE];
	metadata m;
	uint8_t protocol;
	data_packet_to_raw_data(data_packet, &protocol, data, &m, NULL,NULL);
	read_msg_metadata_from_data(m.meta_data, &msg_m);
	uint8_t uname[NAME_SIZE];
	uint8_t rcpt_name[NAME_SIZE];
	read_msg_metadata(&msg_m, (char *)uname,(char *)rcpt_name);
	strcat((char *)uname,"_pub.key");
	char keyfilename[strlen((char *)uname)+1];
	for(int i = 0; i<strlen((char *)uname); i++) {
		keyfilename[i] = uname[i];
	}
	keyfilename[strlen((char *)uname)] = '\0';
	uint8_t token[MAX_DATA_SIZE];
	uint8_t newtoken[MAX_DATA_SIZE];
	fillrandom(token,MAX_DATA_SIZE);
	mpz_t user_public_key;
	bool key_exists = read_key_from_file(user_public_key, keyfilename);
	if(key_exists) {
		send_ack(socket_descriptor, LOGIN_ACK);
		send_enc_login_token(token, user_public_key, socket_descriptor);
		mpz_t public_key;
		read_local_public_key_from_file(public_key);
		mpz_t private_key;
		read_local_private_key_from_file(private_key);
		receive_enc_login_token(newtoken,public_key, private_key,socket_descriptor);
		bool equal_tokens = true;
		for(int i = 0; i<MAX_DATA_SIZE; i++) {
			if(token[i] != newtoken[i]) {
				equal_tokens = false;
			}
		}
		if(equal_tokens) {
			send_ack(socket_descriptor, LOGIN_ACK);
			printf("user %s successfuly logged in\n", uname);
			logged_in = true;
			sem_wait(socket_map_sem);
			hash_add(*socket_map, uname, strlen((char*)uname), &mail_socket_descriptor, sizeof(uint32_t));
			sem_post(socket_map_sem);
		}else{
			send_ack(socket_descriptor, LOGIN_NACK);
			printf("user %s failed to log in\n", uname);
		}
	}else{
		printf("keynotexists\n");
		send_ack(socket_descriptor, LOGIN_NACK);
		printf("user %s not found\n", uname);
	}
	return logged_in;
}

void handle_register(data_packet *data_packt,uint32_t socket_descriptor){
	char username[NAME_SIZE];
	int len;
	mpz_t public_key;
	read_register_name(data_packt,username,&len,public_key);
	remove_newline(username,NAME_SIZE);
	gmp_printf("recieved register request from %s\n",username);
	char cpyd_uname[NAME_SIZE];
	strcpy((char*)cpyd_uname,username);
	char *keyfilename =strcat(username,"_pub.key");
	if(access(keyfilename, F_OK)!=-1) {
		printf("user already registered\n");
		send_ack(socket_descriptor,REGISTER_PROT_NACK);
	}else{
		printf("user %s has been registered\n",cpyd_uname);
		write_key_to_file(public_key,keyfilename);
		send_ack(socket_descriptor,REGISTER_PROT_ACK);
	}
	mpz_clear(public_key);
}
void read_register_name(data_packet *data_packt,char* username,int *len, mpz_t pub_key){
	metadata meta;
	uint8_t protocol;
	uint8_t data[MAX_DATA_SIZE];
	data_packet_to_raw_data(data_packt,&protocol,data,&meta,NULL,NULL);
	msg_metadata namedata;
	read_msg_metadata_from_data(meta.meta_data,&namedata);
	char rcpt_name[NAME_SIZE];
	/**len = namedata.name_len;
	   for(int i = 0; i<namedata.name_len; i++) {
	        username[i] = namedata.rcpt_name[i];
	   }*/
	read_msg_metadata(&namedata, username, rcpt_name);
	*len = namedata.src_name_len;
	mpz_init(pub_key);
	mpz_import(pub_key,meta.data_len,1,sizeof(uint8_t),1,0,data);
}

void send_pub_key_to_client(mpz_t pub_key,uint32_t socket_descriptor){
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

	int val = 1;
	setsockopt(sd, SOL_SOCKET,SO_REUSEPORT | SO_REUSEADDR, &val, sizeof(val));
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
