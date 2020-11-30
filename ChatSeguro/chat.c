#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "MyEncrypt.h"
#include <pthread.h>
#include <semaphore.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <sys/socket.h> 
#define PORT 8080
#define DELIM "|" 
sem_t sm_MAIN;//lock para impedir a função main executar antes das outras threads finalizarem
//funcao para separar a mensagem recebida
void parse(char *buff,char **saveParsed)
{
	char *copy,*p;
	int cnt = 0;
	copy = strdup(buff);
	while(p = strsep(&copy,DELIM))
  	{	
  		saveParsed[cnt] = strdup(p);
  		cnt++;
  	}
  	free(copy);
}

int createClientSocket()
{
	int sock = 0; 
	struct sockaddr_in serv_addr;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{ 
		printf("\n Socket creation error \n"); 
		return -1; 
	} 

	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_port = htons(PORT); 
	
	// Convert IPv4 and IPv6 addresses from text to binary form 
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
	{ 
		printf("\nInvalid address/ Address not supported \n"); 
		return -1; 
	} 
	
	while((connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)) 
	{ 
		printf("\nConnection Failed \n");
	}
	return sock;
}

int createServerSocket(struct sockaddr_in *address, int addrlen)
{
    int server_fd, valread;  
    int opt = 1; 
    char buffer[1024] = {0};
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    (*address).sin_family = AF_INET; 
    (*address).sin_addr.s_addr = INADDR_ANY; 
    (*address).sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)address,  
                                 sizeof(*address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }
    return  server_fd;
}

//Thread que inicia a conexao
void *requestThread()
{
	int sock = createClientSocket();
	int valread;
	char *serverMessageParsed[3];
	unsigned char decrypted[4150]={};
	unsigned char encrypted[4150]={};
	char buff[4200];
	char crypt_len[20];
	char *publicKey;
    	char *privateKey;
    	char serverPrivateKey[4150];
	int decrypted_length;
	int encrypted_length;
	publicKey = getKey("ClientPublic.pem");
    	privateKey = getKey("ClientPrivate.pem");
    	//Troca de chaves
	sprintf(buff,"0%s%s%s",DELIM,privateKey,DELIM);
	//Envia sua propria chave privada
	send(sock , buff , 4200 , 0 ); 
	
	//Recebe a chave privada do servidor
	valread = read(sock , buff, 4200);
	parse(buff,serverMessageParsed);
	strncpy(serverPrivateKey,serverMessageParsed[1],4200);
	
	//envia mensagem no formato 1|ola do cliente| criptografada
	sprintf(buff,"1%s%s%s",DELIM,"Ola do cliente",DELIM);
	encrypted_length = private_encrypt(buff,strlen(buff),serverPrivateKey,encrypted);
	sprintf(crypt_len,"%d",encrypted_length);
	send(sock , encrypted , encrypted_length , 0 ); 
	send(sock,crypt_len,20,0);
	
	//recebe mensagem ola do servidor
	valread = read(sock , buff, 4200); 
	valread = read(sock,crypt_len, 20);
	encrypted_length = atoi(crypt_len);
	decrypted_length = public_decrypt(buff,encrypted_length,publicKey, decrypted);
	parse(decrypted,serverMessageParsed);
	dprintf(1,"================Client received %s===================\n",serverMessageParsed[1]);
	
	//envia mensagem "pare"
	sprintf(buff,"3%s%s%s",DELIM,"pare",DELIM);
	encrypted_length = private_encrypt(buff,strlen(buff),serverPrivateKey,encrypted);
	sprintf(crypt_len,"%d",encrypted_length);
	send(sock , encrypted , encrypted_length , 0 );
	send(sock,crypt_len,20,0);
	
	close(sock);
}


//Thread que escuta
void *listenThread()
{
	struct sockaddr_in address; 
	int addrlen = sizeof(address);
	int new_socket,valread;
	char *clientMessageParsed[3];
	char buff[4200];
	char *publicKey;
    	char *privateKey;
    	char clientPrivateKey[4200];
    	char crypt_len[20];
    	int decrypted_length;
	int encrypted_length;
	unsigned char decrypted[4200]={};
	unsigned char encrypted[4200]={};
    	publicKey = getKey("ServerPublic.pem");
    	privateKey = getKey("ServerPrivate.pem");
	int sock = createServerSocket(&address,addrlen);
	//aceita o socket do cliente
    	if ((new_socket = accept(sock, (struct sockaddr *)&address,(socklen_t*)&addrlen))<0) 
    	{ 
        	perror("accept"); 
        	sem_post(&sm_MAIN);
        	exit(EXIT_FAILURE); 
    	} 
    	
    	//recebe a primeira mensagem do cliente no formato 0|<privateKey>
	valread = read(new_socket , buff, 4200); 
	parse(buff,clientMessageParsed);
	//armazena a chave privada do cliente
	strncpy(clientPrivateKey,clientMessageParsed[1],4200);
	
	//manda a chave privada do servidor
	sprintf(buff,"0%s%s%s",DELIM,privateKey,DELIM);
	send(new_socket , buff , strlen(buff) , 0 );
	
	//recebe mensagem do cliente
	valread = read(new_socket , buff, 4200);
	//recebe o tamanho da mensagem encryptada
	valread = read(new_socket,crypt_len, 20);
	encrypted_length = atoi(crypt_len);
	//desencripta a mensagem do cliente usando a chave publica do servidor
	decrypted_length = public_decrypt(buff,encrypted_length,publicKey,decrypted);
	parse(decrypted,clientMessageParsed);
	dprintf(1,"Servidor recebeu: %s,%s\n",clientMessageParsed[0],clientMessageParsed[1]);
	
	//Envia mensagem encriptada com a chave privada do cliente
	sprintf(buff,"2%s%s%s",DELIM,"Ola do servidor",DELIM);
	encrypted_length = private_encrypt(buff,strlen(buff),clientPrivateKey,encrypted);
	sprintf(crypt_len,"%d",encrypted_length);
	send(new_socket , encrypted , encrypted_length , 0 );
	send(new_socket,crypt_len,20,0);
	
	//lê a mensagem de pare do cliente
	valread = read(new_socket , buff, 4200); 
	valread = read(new_socket,crypt_len, 20);
	encrypted_length = atoi(crypt_len);
	decrypted_length = public_decrypt(buff,encrypted_length,publicKey, decrypted);
	parse(decrypted,clientMessageParsed);
	dprintf(1,"Servidor recebeu: %s,%s\n",clientMessageParsed[0],clientMessageParsed[1]);
	if(!(strcmp(clientMessageParsed[1],"pare")))
	{
		close(new_socket);
		close(sock);
		sem_post(&sm_MAIN);	
	}
}



int main()
{
    sem_init(&sm_MAIN,0,0);
    pthread_t thread_id;
    pthread_create(&thread_id,NULL,requestThread,NULL);
    pthread_create(&thread_id,NULL,listenThread,NULL);
    printf("OK\n");
    sem_wait(&sm_MAIN);
    printf("OK2\n");
    exit(0);
}
