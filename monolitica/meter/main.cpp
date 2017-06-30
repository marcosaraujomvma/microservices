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

int main(void){

    int metering;// value of mettering
    char id_meter[100]; // identificafdor unico do medidor
    char* pkg;
    char build_pkg[2048];// auxiliar
    char* pkg_send;



    unsigned char content;


    //geração da estrtura da chave publica
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    mbedtls_pk_free(&pk);
    //geração da estrtura da chave publica

    mbedtls_pk_context pk_pub;//para a chave publica
    mbedtls_pk_init( &pk_pub );
    mbedtls_pk_free(&pk_pub);
    // fim da geração da estrutu da chave publica

    unsigned char sig[4096]; // saida da assinatura, essa é a vareavel de saida
    unsigned char to_send[1024]; // variavel de saida da criptografia

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



     unsigned char dst[10000]; // variavel de saido do hash, essa variavel é o hash
     size_t b64olen = 0;// olen do base  64
     size_t olen = 0; // olen da assinatura e criptografia


    // carregar a chave privada do medidorr
    if ((mbedtls_pk_parse_keyfile(&pk,
                                "keys/meter_private.pem",
                                NULL))==0){
        printf("LOADED PRIVATE KEY\n");

    }else{
        printf("ERRO!!! NO LOAD PRIVATE KEY\n");
    }




    // carrega a chave publica da nuvem
    if ((mbedtls_pk_parse_public_keyfile(&pk_pub,
                                        "keys/cloud_public.pem"))==0){
        printf("LOADED CLOUD PUBLIC KEY\n");

    }else{
        printf("ERRO!!! NO LOAD CLOUD PUBLIC KEY\n");
    }



    printf("Enter the meter id:\n\n");
    fgets(id_meter,100,stdin);

    while(1){

        // socket aqui


      int clientSocket;
	  char buffer[1048576];// buffer do socket para enviar ate 1 mega
	  memset(buffer, '\0',1048576); // zera o buffer do socket
      struct sockaddr_in serverAddr; // estrutura do socket
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

        mbedtls_sha256((const unsigned char*)pkg,
                        tamanho,
                        output,
                        is224);
        /* fim Generates the hash */




        // processo de assinar o pacote
        if ((mbedtls_pk_sign(&pk,
                            MBEDTLS_MD_SHA256,
                            output,
                            sizeof(output),
                            sig,
                            &olen,
                            mbedtls_ctr_drbg_random,
                            &ctr_drbg))==0){

            printf("Success in the process of signing! \n\n");
        }
        // fim do processo de criptografar o hash

        olen = 0;

        int ret; // variavel usada para teste de retorno

        char error_str[256]; // variavel de string de erro


        snprintf(build_pkg,sizeof(build_pkg),"%s;%d;%s",id_meter,metering,sig); //pkg


        //pkg = build_pkg; //pkg to sign
        printf("Pacote para criptografar: %s\n",build_pkg);

        // processo de criptografar o pacote
        if ((ret = mbedtls_pk_encrypt(&pk_pub,
                                (unsigned char *)build_pkg,
                                olen,
                                to_send,
                                &olen,
                                sizeof(to_send),
                                mbedtls_ctr_drbg_random,
                                &ctr_drbg))==0){

            printf("Success in the process of CRYPT! \n\n");
        }else{
            printf("ERROOOOOOOOO in the process of CRYPT! \n\n");
        }

        // FIM processo de criptografar o pacote


        mbedtls_strerror(ret, error_str, sizeof error_str);//verificar os erros
        printf("%s\n",error_str);// printa o erro


        // codifica em base 64 para enviar os  dados
        if ((mbedtls_base64_encode(dst,
                                sizeof(dst),
                                &b64olen,
                                to_send,
                                sizeof(to_send)))==0){
            printf("SUCESSO BASE 64\n\n");
            //printf("Assinatura em base64: %s \n\n",dst);
            }



        printf("base64: %s\n",dst);
        send(clientSocket, dst, sizeof dst, 0); // envia o pacote para o servidor
        close(clientSocket);

        printf("\nSent with success!!\n\
        ====================================================================\n");
            //}

    }

    return 0;
}
