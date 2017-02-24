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
#include <openssl/hmac.h>

int  clientSocket;
char *content;
char *finalContent;
unsigned char *md;
unsigned int md_length;

void print_bytes(unsigned char* buf, int len) {
  int i;
  for (i=0; i<len;i++)
    if(i!=len-1)
      printf("%02X:",buf[i]);
    else
       printf("%02X\n",buf[i]);
}

int computeFileSize(char *fileName) {
  FILE *fd;
  int sz;
  fd=fopen(fileName, "r");

  if( fd == NULL ) {
    perror("Errore in apertura del file");
    exit(1);
  }

  fseek(fd, 0, SEEK_END);
  sz = ftell(fd);
  fseek(fd, 0, SEEK_SET);
  fclose(fd);
  return sz;
}

void writeOnFile(char *fileName, unsigned char* keyValue, int keysize) {

  FILE *fd;
  int i;

  fd = fopen(fileName, "w");

     if( fd==NULL ) {
      perror("Errore in apertura del file");
      exit(1);
     }

     for (i=0; i<keysize;i++)
       fprintf(fd,"%c",keyValue[i]);

  fclose(fd);
}

void readPlaintext(char *fileName) {

  FILE *fd;
  int i,j,a;
  i=j=a= 0;

  fd = fopen(fileName, "r");

    if( fd == NULL ) {
      perror("Errore in apertura del file");
      exit(1);
    }

    while(!feof(fd)) 
     fscanf(fd,"%c",&content[i++]);

    printf("PLAINTEXT: ");
    print_bytes((unsigned char *)content,computeFileSize("input.txt"));

    printf("\n");

    fclose(fd);
}

void concatenatePlaintextToMessageDigest(char *fileName) {

  FILE *fd;
  int i;
  i=0;

  fd = fopen(fileName, "r");

    if( fd == NULL ) {
      perror("Errore in apertura del file");
      exit(1);
    }

    while(!feof(fd)) 
     fscanf(fd,"%c",&finalContent[i++]);

    memcpy((void*)finalContent+computeFileSize("input.txt"),md,md_length);

    fclose(fd);
}


void initializeContentBuffer() {
   
    content = (char *) malloc(computeFileSize("input.txt"));
}

void initializeFinalBuffer(int md_length) {
    finalContent = (char *) malloc(computeFileSize("input.txt")+md_length);
}

int main(int argc, char* argv[]) {

 unsigned char *ciphertext;
 struct sockaddr_in server;
 int yes,ret;
 int key_size_encryption,key_size_authentication,block_size,cipher_len;
 int outlen_tot,outlen;

 unsigned char key [EVP_MAX_KEY_LENGTH];
 unsigned char key_auth [EVP_MAX_KEY_LENGTH];

 if( (clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("A problem occured while creating Socket related to the Server!");           
    exit(1);
 }

  //Settaggio opzioni associate con la socket: Se indirizzo già in uso ritorno Errore
  if(setsockopt(clientSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    perror("A problem occured while performing SETSOCKOPT() FUNCTION"); 
    close(clientSocket);
    exit(1);
  }

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons(1234);
  inet_pton(AF_INET,"127.0.0.1",&server.sin_addr.s_addr);

   ret = connect(clientSocket, (struct sockaddr *)&server, sizeof(server));
   if(ret < 0) {
    perror("A problem occured while performing CONNECT() FUNCTION!");
    close(clientSocket);
    exit(1);
   }

   printf("\nConnessione al server %s (porta: %s) effettuata con successo ","127.0.0.1","1234");
   printf("\n");

    
    block_size = EVP_CIPHER_block_size(EVP_des_ecb());
    key_size_encryption = EVP_CIPHER_key_length(EVP_des_ecb());
    key_size_authentication = EVP_MD_size(EVP_md5());

     RAND_bytes(key,key_size_encryption);
     RAND_bytes(key_auth,key_size_authentication);

     writeOnFile("key.txt",key, EVP_MAX_KEY_LENGTH);
     writeOnFile("key_auth.txt",key_auth, EVP_MAX_KEY_LENGTH);
     printf("\n");
     printf("======= STARTING DES ENCODING =======");
     printf("\n\n");

     EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
     EVP_CIPHER_CTX_init(ctx);

     HMAC_CTX* hmac_ctx;
     hmac_ctx = malloc(sizeof(HMAC_CTX));
     HMAC_CTX_init(hmac_ctx);

     HMAC_Init(hmac_ctx, key_auth, key_size_authentication, EVP_md5());
     initializeContentBuffer();
     readPlaintext("input.txt");
     HMAC_Update(hmac_ctx, (unsigned char *) content, computeFileSize("input.txt"));
     md = malloc(EVP_MD_size(EVP_md5()));
     HMAC_Final(hmac_ctx, md, &md_length);
     printf("MESSAGE DIGEST: ");
     print_bytes(md,md_length);
     printf("\n");

     EVP_EncryptInit(ctx,EVP_des_ecb(),NULL,NULL);
     EVP_EncryptInit(ctx,NULL,key,NULL);
    
     ciphertext = (unsigned char*)malloc(computeFileSize("input.txt")+md_length+block_size);

     initializeFinalBuffer(md_length);
     concatenatePlaintextToMessageDigest("input.txt");

     outlen_tot = outlen = 0;
     EVP_EncryptUpdate(ctx,ciphertext,&outlen,(unsigned char *)finalContent,computeFileSize("input.txt")+md_length);
     outlen_tot += outlen;

     EVP_EncryptFinal(ctx,ciphertext+outlen_tot,&outlen);
     outlen_tot += outlen;
     cipher_len = outlen_tot;

     EVP_CIPHER_CTX_cleanup(ctx);

     int *dim = &cipher_len;

     printf("DES KEY: ");
     print_bytes(key,key_size_encryption);
     printf("\n");

     printf("AUTHENTICATION KEY: ");
     print_bytes(key_auth,key_size_authentication);
     printf("\n");


     printf("CIPHERTEXT: ");
     print_bytes(ciphertext,cipher_len);

     //writeOnFile("encrypted.txt",ciphertext,cipher_len);
     //printf("Cipher text size: %d bytes",cipher_len);

     printf("\n");
     printf("======= END DES ENCODING =======");
     printf("\n\n");
     printf("CONTACTING SERVER................");
     printf("\n");
   	 printf("\nSENDING ENCRYPTED MESSAGE................");

     //send size to the server to allocate the rcvBuffer
     ret = send (clientSocket,(void *)dim,sizeof(int),0);

     if( (ret == -1 || (ret < sizeof(int)))  ){
      perror("Error while executing send()!\n\n"); 
      close(clientSocket);
      exit(1);
    }

    int plaintext_size = computeFileSize("input.txt")+md_length;
    int *p_plaintext_size = &plaintext_size;

    ret = send (clientSocket,(void *)p_plaintext_size,sizeof(int),0);

     if( (ret == -1 || (ret < sizeof(int)))  ){
      perror("Error while executing send()!\n\n"); 
      close(clientSocket);
      exit(1);
    }

    //printf("size: %d\n",*dim);
    //printf("Size has been sent!\n");
    
   	ret = send(clientSocket,(void*)ciphertext,*dim, 0);

	  if( (ret == -1) || (ret <*dim)  ){
		 perror("Error while executing send()!\n\n"); 
		 close(clientSocket);
		 exit(1);
	  }

	 printf("SENT!\n");
   printf("\n");

   free(ctx);
   free(ciphertext);
   free(content);
   HMAC_CTX_cleanup(hmac_ctx);
   free(hmac_ctx);
   free(finalContent);
   
	 return 0;
}