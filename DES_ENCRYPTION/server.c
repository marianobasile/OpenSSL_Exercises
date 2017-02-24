#include <stdlib.h>
#include <stdio.h>																							
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

unsigned char key [EVP_MAX_KEY_LENGTH];

void print_bytes(unsigned char* buf, int len) {
  int i;
  for (i=0; i<len;i++)
    if(i!=len-1)
      printf("%02X:",buf[i]);
    else
       printf("%02X\n",buf[i]);
}

void initializeKey() {
	FILE *fd;
  	int i,j;
  	i=j=0;

  	fd=fopen("key.txt", "r");

     if( fd == NULL ) {
      perror("Errore in apertura del file");
      exit(1);
     }

     while(!feof(fd)) {
      fscanf(fd,"%c",&key[i++]);
     }

     printf("DES KEY: ");
     print_bytes(key,8);
     printf("\n");

  fclose(fd);
}

void writeOnFile(char *fileName, unsigned char* plaintext,int plain_length) {

  FILE *fd;
  int i;

  fd = fopen(fileName, "w");

     if( fd==NULL ) {
      perror("Errore in apertura del file");
      exit(1);
     }
    

     for (i=0; i<plain_length;i++)
       fprintf(fd,"%c",plaintext[i]);

  fclose(fd);
}
int main(int argc, char* argv[]) {

	int listeningSocket; 			  //Socket su cui il server si mette in ascolto
	int connectionSocket;			  //Socket relativa alla connesione stabilita
	struct sockaddr_in serverAddr;    //Struttura dati per memorizzare Indirizzo Server (ip_addr + port)
	struct sockaddr_in clientAddr;	  //Struttura dati per memorizzare Indirizzo Client (ip_addr + port)
	int clientAddrLen;				  //Dimensione della struttura che contiene indirizzo client
	int yes;						  //REUSE_ADDR in setsockopt richiede un parametro intero per optval
	int outlen_tot,outlen;

	if( (listeningSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {					
			perror("A problem occured while creating Server Socket!\n\n");
			exit(1);
	}

	//Settaggio opzioni associate con la socket
	if(setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("Server Address already in use!\n\n"); 
		close(listeningSocket);
		exit(1);
	}

	memset(&serverAddr,0,sizeof(serverAddr));

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(1234);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if( bind(listeningSocket,(struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
			perror("Error while executing bind():"); 
			close(listeningSocket);
			exit(1);
	}

	printf("\nIndirizzo: %s (Porta: %s)\n\n","127.0.0.1","1234");

	if( listen(listeningSocket,10) <0) {
		perror("Error while executing listen()!\n\n"); 
		close(listeningSocket);
		exit(1);
	}

	memset(&clientAddr, 0, sizeof(clientAddr));
	clientAddrLen = sizeof(clientAddr);

	if( (connectionSocket = accept(listeningSocket,(struct sockaddr *)&clientAddr,(socklen_t *)&clientAddrLen)) < 0 ) {
		perror("Error while executing connect()!\n\n"); 
		close(listeningSocket);
		exit(1);
	}

	int encryptedMsgSize;
	int plaintextMsgSize;
  	int ret;

  	ret = recv(connectionSocket, (void *)&encryptedMsgSize, sizeof(int), MSG_WAITALL);

  	if( (ret == -1) || (ret < sizeof(int)) ){
		perror("Error while executing recv1()!\n\n"); 
		close(listeningSocket);
		exit(1);
	}

	ret = recv(connectionSocket, (void *)&plaintextMsgSize, sizeof(int), MSG_WAITALL);

  	if( (ret == -1) || (ret < sizeof(int)) ){
		perror("Error while executing recv1()!\n\n"); 
		close(listeningSocket);
		exit(1);
	}

	//printf("size: %d\n",encryptedMsgSize);

	unsigned char encryptedMsg[encryptedMsgSize];
	memset(encryptedMsg,0,encryptedMsgSize);

	ret = recv(connectionSocket, (void*)encryptedMsg,encryptedMsgSize, MSG_WAITALL);

	if( (ret == -1) || (ret < encryptedMsgSize)){
		perror("Error while executing recv2()!\n\n"); 
		close(listeningSocket);
		exit(1);
	}
		printf("CIPHERTEXT: ");
		print_bytes(encryptedMsg,encryptedMsgSize);
		printf("\n");

	unsigned char *plaintext;
	int block_size =EVP_CIPHER_block_size(EVP_des_ecb());
	plaintext = (unsigned char*)malloc(plaintextMsgSize+block_size);

	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(ctx);

    initializeKey();
    EVP_DecryptInit(ctx,EVP_des_ecb(),key,NULL);

    outlen_tot = outlen = 0;
	EVP_DecryptUpdate(ctx,plaintext,&outlen,encryptedMsg,encryptedMsgSize);
    outlen_tot += outlen;

    int res;
    res = EVP_DecryptFinal(ctx,plaintext+outlen_tot,&outlen);
    if(res == 0) {
    	perror("error while decrypting!!\n");
    	close(listeningSocket);
    	exit(1);
    }
    outlen_tot += outlen;
    //printf("Plaintext size: %d\n",outlen_tot);
    //printf("Plaintext: %s\n",plaintext);
    //print_bytes(plaintext,outlen_tot);

    writeOnFile("Client.txt",plaintext,outlen_tot);
    /*printf("PLAINTEXT: ");
    int j;
    for(j=0; j<outlen_tot; j++)
    	printf("%c",plaintext[j]);
    	printf("\n");*/
    
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
    free(plaintext);
    
	return 0;
}
