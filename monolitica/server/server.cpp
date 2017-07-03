/****************** SERVER CODE ****************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include "include/mbedtls/base64.h"
#include "include/mbedtls/error.h"
#include "include/mbedtls/pk.h"
#include "include/mbedtls/entropy.h"
#include "include/mbedtls/ctr_drbg.h"

int main(){
  int welcomeSocket, newSocket; // criar o socket
  unsigned char buffer[136800]; // buffer do socket
  memset(buffer, '\0',136800);
  unsigned char buffer_rec[16800]; // bufer que rece os dados
  memset(buffer_rec, '\0',sizeof(buffer_rec)); // zera o buffer que receb os dados
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  socklen_t addr_size;

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  welcomeSocket = socket(PF_INET, SOCK_STREAM, 0);

  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(10010);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

  /*---- Bind the address struct to the socket ----*/
  bind(welcomeSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

  /*---- Listen on the socket, with 8192 max connection requests queued ----*/
  if(listen(welcomeSocket,8192)==0)
    printf("Listening\n");
  else
    printf("Error\n");

    //geração da estrtura da chave privada da nuvem
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    mbedtls_pk_free(&pk);

    // carregar a chave privada da nuvem

    mbedtls_pk_context pk_pub;//para a chave publica
    mbedtls_pk_init( &pk_pub );
    mbedtls_pk_free(&pk_pub);
    // fim da geração da estrutu da chave publica



                /*Geração da entropia*/
     mbedtls_ctr_drbg_context ctr_drbg;
     mbedtls_ctr_drbg_free(&ctr_drbg);
     mbedtls_ctr_drbg_init( &ctr_drbg );

     mbedtls_entropy_context entropy;
     mbedtls_entropy_init(&entropy);

     mbedtls_ctr_drbg_seed(&ctr_drbg,
                            mbedtls_entropy_func,
                            &entropy,
                            NULL,
                            0);

            /*FIM Entropia*/


    if ((mbedtls_pk_parse_keyfile(&pk,
                                "keys/cloud_private.pem",
                                NULL))==0){
        printf("LOADED PRIVATE KEY\n");

    }else{
        printf("ERRO!!! NO LOAD PRIVATE KEY\n");
    }


    // carrega a chave publica do medidor
    if ((mbedtls_pk_parse_public_keyfile(&pk_pub,
                                        "keys/meter_public.pem"))==0){
        printf("LOADED METER PUBLIC KEY\n");

    }else{
        printf("ERRO!!! NO LOAD CLOUD PUBLIC KEY\n");
    }




  unsigned char b64decode[4096]; // variavel de saida do decode do base 64
  size_t b64olen = 0;

  size_t olen = 0;
  int ret = 0;
  char error_str[256];
  unsigned char* output_decrypt;


   while (1){
	  /*---- Accept call creates a new socket for the incoming connection ----*/
	  addr_size = sizeof serverStorage;
	  newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);

      recv(newSocket, buffer_rec, sizeof(buffer_rec), 0);
      //printf("%s",
      printf("Tamanho do buffer  %i",sizeof buffer_rec);
	  printf("Data received: %s\n\n",buffer_rec);
/*

	  ret = mbedtls_base64_decode(  b64decode,
                                    sizeof(b64decode),
                                    &b64olen,
                                    buffer_rec,
                                    sizeof(buffer_rec));

     if (ret == 0){
        printf("Base 64 decodificado com sucesso!!\n");
        }else{
        printf("ERRO de decodificar o base 64!!\n");

        mbedtls_strerror(ret, error_str, sizeof error_str);//verificar os erros
        printf("%s\n",error_str);// printa o erro
        }
    printf("======\nSAIDA DO BASE 64  %s\n\n======",b64decode);
    /*---- Send message to the socket of the incoming connection ----*/

    size_t b64olen = 0;

    ret = mbedtls_pk_decrypt(&pk,
                            (unsigned char*)buffer_rec,
                            sizeof(buffer_rec),
                            (unsigned char*)output_decrypt,
                            &olen,
                            sizeof(output_decrypt),
                            mbedtls_ctr_drbg_random,
                            &ctr_drbg);

     if (ret == 0){
        printf("RSA decodificado com sucesso!!\n");
        }else{
        printf("ERRO de decodificar o RSA!\n");

        mbedtls_strerror(ret, error_str, sizeof error_str);//verificar os erros
        printf("%s\n",error_str);// printa o erro
        }
	  //strcpy(buffer,"Hello World\n");
	  send(newSocket,buffer,13,0);
	  //close(newSocket);
	}
  return 0;
}

