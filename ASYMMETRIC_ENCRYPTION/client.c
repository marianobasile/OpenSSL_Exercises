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
#include <openssl/pem.h>

int  clientSocket;
char *content;

void print_bytes(unsigned char* buf, int len) {
  int i;
  for (i=0; i<len;i++)
    if(i!=len-1)
      printf("%02X:",buf[i]);
    else
       printf("%02X\n",buf[i]);
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

void readFromFile(char *fileName) {

  FILE *fd;
  int i,j;
  i=j=0;

  fd = fopen(fileName, "r");

    if( fd == NULL ) {
      perror("Errore in apertura del file");
      exit(1);
    }

    while(!feof(fd)) 
     fscanf(fd,"%c",&content[i++]);

    printf("PLAINTEXT: ");
    for(j=0;j<i;j++)
      printf("%c",content[j]);
    printf("\n");

    fclose(fd);
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

void initializeContentBuffer() {
    content = (char *) malloc(computeFileSize("input.txt"));
}

int main(int argc, char* argv[]) {

 unsigned char *ciphertext;
 struct sockaddr_in server;
 int yes,ret;
 int key_size,block_size,cipher_len;
 int outlen_tot,outlen;

 unsigned char key [EVP_MAX_KEY_LENGTH];

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
  server.sin_port = htons(1235);
  inet_pton(AF_INET,"127.0.0.1",&server.sin_addr.s_addr);

   ret = connect(clientSocket, (struct sockaddr *)&server, sizeof(server));
   if(ret < 0) {
    perror("A problem occured while performing CONNECT() FUNCTION!");
    close(clientSocket);
    exit(1);
   }

   printf("\nConnessione al server %s (porta: %s) effettuata con successo ","127.0.0.1","1235");
   printf("\n");

   //==== Allocates the pub key ======
   FILE * fd = fopen("rsa_pubkey.pem","r");
   if( fd==NULL ) {
      perror("Errore in apertura del file");
      exit(1);
   }

   EVP_PKEY* evp_pkey = PEM_read_PUBKEY(fd, NULL, NULL,NULL);
   
   if(evp_pkey != NULL)
    printf("\n==== EVP_PKEY CORRECTLY ALLOCATED!! ====\n");

   EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
   EVP_CIPHER_CTX_init(ctx);

    //=== encrypted symmetric key  buffer length
    int ekl; 

   //=== encrypted symmetric key  buffer
   unsigned char *ek[1];
   ek[0] = malloc(EVP_PKEY_size(evp_pkey));
  
   //== generated iv
   unsigned char* iv = malloc(EVP_CIPHER_iv_length(EVP_des_cbc()));

  EVP_PKEY* pubk[1];
  //pubk[0] = malloc(EVP_PKEY_size(evp_pkey));
  pubk[0] = evp_pkey;

   if( EVP_SealInit(ctx,EVP_des_cbc(),ek, &ekl, iv, pubk, 1) != 0);
    printf(" ==== SealInit successfully initialized!!\n ==== ");

   ciphertext = (unsigned char*)malloc(computeFileSize("input.txt")+block_size);
   outlen_tot = outlen = 0;

   initializeContentBuffer();
   readFromFile("input.txt");

   if( EVP_SealUpdate(ctx,ciphertext, &outlen, (unsigned char *)content,computeFileSize("input.txt")) != 0)
      printf(" ==== SealUpdate successfully executed!!\n ==== ");
   outlen_tot += outlen;

   EVP_SealFinal(ctx, ciphertext+outlen_tot, &outlen);
    printf(" ==== SealFinal successfully executed!!\n ==== ");
   outlen_tot += outlen;
   cipher_len = outlen_tot;


     printf("CIPHERTEXT: ");
     print_bytes(ciphertext,cipher_len);

     //writeOnFile("encrypted.txt",ciphertext,cipher_len);
     //printf("Cipher text size: %d bytes",cipher_len);

     printf("\n");
     printf("CONTACTING SERVER................");
     printf("\n");
   	 printf("\nSENDING ENCRYPTED MESSAGE................\n\n");

     //send size to the server to allocate the rcvBuffer
    
     int *dim = &cipher_len;
     ret = send (clientSocket,(void *)dim,sizeof(int),0);

     if( (ret == -1 || (ret < sizeof(int)))  ){
      perror("Error while executing send()!\n\n"); 
      close(clientSocket);
      exit(1);
    }

    int plaintext_size = computeFileSize("input.txt");
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

    //====================
    printf("ek length: %d\n\n",ekl);
    ret = send (clientSocket,(void *)&ekl,sizeof(int),0);

     if( (ret == -1 || (ret < sizeof(int)))  ){
      perror("Error while executing send()!\n\n"); 
      close(clientSocket);
      exit(1);
    }

    //printf("size: %d\n",*dim);
    //printf("Size has been sent!\n");
    printf("Symmetric encrypypted key: ");
    print_bytes(ek[0],ekl);
    printf("\n");
    ret = send(clientSocket,(void*)ek[0],ekl, 0);

    if( (ret == -1) || (ret < ekl ) ){
     perror("Error while executing send()!\n\n"); 
     close(clientSocket);
     exit(1);
    }
    //====================
    int iv_size = EVP_CIPHER_iv_length(EVP_des_cbc());
    int *p_iv_size = &iv_size;

    printf("iv length: %d\n",iv_size);
    ret = send (clientSocket,(void *)p_iv_size,sizeof(int),0);

     if( (ret == -1 || (ret < sizeof(int)))  ){
      perror("Error while executing send()!\n\n"); 
      close(clientSocket);
      exit(1);
    }

    printf("\nInitialization Vector: ");
    print_bytes(iv,iv_size);
    printf("\n");
    ret = send(clientSocket,(void*)iv,iv_size, 0);

    if( (ret == -1) || (ret <iv_size)  ){
     perror("Error while executing send()!\n\n"); 
     close(clientSocket);
     exit(1);
    }
    //====================

	 printf("SENT!\n");
   printf("\n");

   free(ctx);
   free(ciphertext);
   free(content);

	 return 0;


}