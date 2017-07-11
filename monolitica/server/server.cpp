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
#include "include/mbedtls/sha256.h"


int main(){
  int welcomeSocket, newSocket; // criar o socket
  unsigned char buffer[1000]; // buffer do socket
  memset(buffer, NULL, 1000);
  unsigned char buffer_rec[1000]; // bufer que rece os dados
  memset(buffer_rec, NULL,sizeof(buffer_rec)); // zera o buffer que receb os dados
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
  if(listen(welcomeSocket,4096)==0)
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




  unsigned char b64decode[512]; // variavel de saida do decode do base 64
  size_t b64olen = 0;

  size_t olen = 0;
  int ret = 0;
  char error_str[256];
  unsigned char output_decrypt[512];
  memset(output_decrypt,NULL,sizeof output_decrypt);


   while (1){
	  /*---- Accept call creates a new socket for the incoming connection ----*/
	  addr_size = sizeof serverStorage;
	  newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);

      recv(newSocket, buffer_rec, sizeof(buffer_rec), 0);
      //printf("%s",
      printf("Tamanho do buffer  %i\n",sizeof buffer_rec);
	  //printf("Data received: %s\n\n",buffer_rec);

    printf("conteudo buffer: %s\n", buffer_rec);

	  ret = mbedtls_base64_decode(  b64decode,
                                    sizeof(b64decode),
                                    &b64olen,
                                    buffer_rec,
                                    684);

     if (ret == 0){
        printf("Base 64 decodificado com sucesso!!\n");
        }else{
        printf("ERRO de decodificar o base 64!!\n");

        mbedtls_strerror(ret, error_str, sizeof error_str);//verificar os erros
        printf("%s\n",error_str);// printa o erro
        }
    printf("======\nSAIDA DO BASE 64  %s\n\n======",b64decode);
    /*---- Send message to the socket of the incoming connection ----*/

    size_t olen_dec = 512;

    ret = mbedtls_pk_decrypt(&pk,
                            b64decode,
                            olen_dec,
                            output_decrypt,
                            &olen_dec,
                            sizeof(output_decrypt),
                            mbedtls_ctr_drbg_random,
                            &ctr_drbg);

     if (ret == 0){
        printf("\nRSA decodificado com sucesso!!\n");
        printf("DECODIFICADO:\n %s\n", output_decrypt);
        }else{
        printf("ERRO de decodificar o RSA!\n");

        mbedtls_strerror(ret, error_str, sizeof error_str);//verificar os erros
        printf("%s\n",error_str);// printa o erro
        }

       char * pch;
           unsigned char stringBuffer[512];
        memset(stringBuffer, NULL, 512);
        int strLength = 0;
        //printf ("Splitting string \"%s\" into tokens:\n",output_decrypt);
        pch = strtok ((char*)output_decrypt,";");
        printf("id: %s\n",pch);
        strLength += snprintf((char*)stringBuffer + strLength, 512-strLength, "%s;",pch);
        pch = strtok (NULL, ";");
        printf("medicao: %s\n",pch);
        strLength += snprintf((char*)stringBuffer + strLength, 512-strLength, "%s;",pch);
        pch = strtok (NULL, ";");
        printf("timestamp: %s\n",pch);
        strLength += snprintf((char*)stringBuffer + strLength, 512-strLength, "%s;",pch);
        pch = strtok (NULL, ";");
        printf("assinatura: %s\n",pch);

      unsigned char buff_sig[128];
      ret = mbedtls_base64_decode(  buff_sig,
                                    sizeof(buff_sig),
                                    &b64olen,
                                    (unsigned char*)pch,
                                    172);



        unsigned char output[32];
        memset(output, NULL,32);

        mbedtls_sha256(stringBuffer,
                        strLength,
                        output,
                        0);



        /*
        ret = mbedtls_base64_encode(buff_sig, 200, &olen, (unsigned char*)pch, sizeof(pch));
        mbedtls_strerror(ret, error_str, sizeof error_str);//verificar os erros
        printf("%s\n",error_str);// printa o erro
        //strLength += snprintf((char*)stringBuffer + strLength, 512-strLength, "%s",sig);
        */
        //printf("\nassinatura base64: %s\n",(char*)buff_sig);


       ret = mbedtls_pk_verify (&pk_pub, MBEDTLS_MD_SHA256, output, 32, buff_sig, sizeof(buff_sig));
       if (ret){
        mbedtls_strerror(ret, error_str, sizeof error_str);//verificar os erros
        printf("%s\n",error_str);// printa o erro
       } else
       printf("assinatura válida\n");// printa o erro


	  //strcpy(buffer,"Hello World\n");
	  send(newSocket,buffer,13,0);
	  //close(newSocket);
	}
  return 0;
}

