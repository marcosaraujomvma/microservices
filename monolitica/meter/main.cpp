/****************** METER CODE ****************/
// Marcos Araújo

#if !defined(MBEDTLS_CONFIG_FILE)
#include "include/mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "include/mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif




#include <iostream>
#include "include/mbedtls/pk.h"
#include "include/mbedtls/entropy.h"
#include "include/mbedtls/ctr_drbg.h"
#include "include/mbedtls/error.h"
#include "include/mbedtls/rsa.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "include/mbedtls/sha256.h"
#include "include/mbedtls/base64.h"

/*
int sendData(unsigned char content[1048576]){

	  int clientSocket;
	  char buffer[1048576];
	  memset(buffer, '\0',1048576);
      struct sockaddr_in serverAddr;
      socklen_t addr_size;


	  /*---- Create the socket. The three arguments are: ----*/
	  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
	  /*
	  clientSocket = socket(PF_INET, SOCK_STREAM, 0);

	  /*---- Configure settings of the server address struct ----*/
	  /* Address family = Internet */
	  /*serverAddr.sin_family = AF_INET;
	  /* Set port number, using htons function to use proper byte order */
	  /*serverAddr.sin_port = htons(10010);
	  /* Set IP address to localhost */
	  /*serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	  /* Set all bits of the padding field to 0 */
	  /*memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	  /*---- Connect the socket to the server using the address struct ----*/
	  /*addr_size = sizeof serverAddr;

	  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);



	  send(clientSocket, content, sizeof(content), 0);


	  /*---- Read the message from the server into the buffer ----*/
	  /*recv(clientSocket, buffer,1048576, 0);

	  /*---- Print the received message ----*/
	  /*printf("Data received: %s\n\n",buffer);
	  close(clientSocket);

	  return 1;


	}


unsigned char* sha256(const unsigned char* input){
    int tamanho = sizeof(input);
	int is224 = 0;
	unsigned char output[32];
	mbedtls_sha256((const unsigned char*)input, tamanho, output,is224);
	printf("output %s\n\n",output);

	return output;
}
*/

int main(void){

    int metering;// value of mettering
    char id_meter[100];
    char* pkg;
    char build_pkg[100];// auxiliar
    char* pkg_send;



    unsigned char content;

    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    mbedtls_pk_free(&pk);
    unsigned char sig[4096];


    mbedtls_pk_context pk_pub;//para a chave publica
    mbedtls_pk_init( &pk_pub );
    //mbedtls_pk_free(&pk_pub);
    //unsigned char sig[4096];


            /*Entropia*/
     mbedtls_ctr_drbg_context ctr_drbg;
     mbedtls_ctr_drbg_free(&ctr_drbg);
     mbedtls_ctr_drbg_init( &ctr_drbg );

     mbedtls_entropy_context entropy;
     mbedtls_entropy_init(&entropy);

     mbedtls_ctr_drbg_seed(&ctr_drbg,mbedtls_entropy_func,&entropy,NULL,0);

            /*FIM Entropia*/


     //base64
     unsigned char dst[1048576];
     //memset(dst, '\0',sizeof(dst));
     //const unsigned char* src;
     size_t b64olen = 0;

     //fim base64


    size_t olen = 0;



    if ((mbedtls_pk_parse_keyfile(&pk,"keys/meter_sign",NULL))==0){
        printf("LOADED PRIVATE KEY\n");

    }else{
        printf("ERRO!!! NO LOAD PRIVATE KEY\n");
    }

    unsigned char** buf;
    size_t bu = 0;

    if ((mbedtls_pk_load_file("keys/cloud_public.pem",buf, &bu ))==0){
        printf("LOADED CLOUD PUBLIC KEY\n");

    }else{
        printf("ERRO!!! NO LOAD CLOUD PUBLIC KEY\n");
    }

    printf("");
/*

    if ((mbedtls_pk_parse_public_keyfile(&pk_pub,"keys/00cloud_public.pem"))==0){
        printf("LOADED CLOUD PUBLIC KEY\n");

    }else{
        printf("ERRO!!! NO LOAD CLOUD PUBLIC KEY\n");
    }
*/


    printf("Enter the meter id:\n\n");
    fgets(id_meter,100,stdin);

    while(1){

        // socket aqui


      int clientSocket;
	  char buffer[1048576];
	  memset(buffer, '\0',1048576);
      struct sockaddr_in serverAddr;
      socklen_t addr_size;


	  /*---- Create the socket. The three arguments are: ----*/
	  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
	  clientSocket = socket(PF_INET, SOCK_STREAM, 0);

	  /*---- Configure settings of the server address struct ----*/
	  /* Address family = Internet */
	  serverAddr.sin_family = AF_INET;
	  /* Set port number, using htons function to use proper byte order */
	  serverAddr.sin_port = htons(10010);
	  /* Set IP address to localhost */
	  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	  /* Set all bits of the padding field to 0 */
	  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	  /*---- Connect the socket to the server using the address struct ----*/
	  addr_size = sizeof serverAddr;

	  connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);

        //fim do socket




        // Stop between packet generation
        sleep(1);

        // generate random number to meter
        metering = 1 + ( rand() % 100 );

        snprintf (build_pkg,sizeof(build_pkg),"%s;%d",id_meter,metering); //pkg


        pkg = build_pkg; //pkg to sign

        /* Generates the hash */
        int tamanho = sizeof((const unsigned char*)pkg);
        int is224 = 0;
        unsigned char output[32];
        memset(output, '0',32);
        mbedtls_sha256((const unsigned char*)pkg, tamanho, output,is224);

    //    if(output)!=0){
      //      printf("HASH OK");
        //}
        //printf("Package hash:  %s \n\n",output);
        /* fim Generates the hash */




        if ((mbedtls_pk_sign(&pk,MBEDTLS_MD_SHA256,output,sizeof(output),sig,&olen,mbedtls_ctr_drbg_random,&ctr_drbg))==0){
            printf("Success in the process of signing! \n\n");
        }
        //printf("tamanho da assinatura %i\n", sizeof(sig));
        //printf("tamanho do pkg %i\n ",sizeof(pkg_send));

        if ((mbedtls_base64_encode(dst,sizeof(dst),&b64olen,sig,sizeof(sig)))==0){
            printf("SUCESSO BASE 64\n\n");
            //printf("Assinatura em base64: %s \n\n",dst);
            }


        send(clientSocket, dst, sizeof dst, 0);
        close(clientSocket);
        printf("Assinatura em base64: %s \n\n",dst);

        //printf("tamanho da base64 %l", sizeof(dst));


        //printf("%i",sizeof(pkg));
        //content = (unsigned char [1048576])sig;
        //stpcpy(content,sig);
//        snprintf (pkg_send,1048576,"%s;%s",pkg,dst);
        //printf("\n%s\n",sig);

        //int return_sendData = sendData(content);
        //if (return_sendData ==1){
          //  printf("%s \nSent with success!!\n=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=\n",pkg_send);
            //}

    }

    return 0;
}
