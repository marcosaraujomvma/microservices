/****************** SERVER CODE ****************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

int main(){
  int welcomeSocket, newSocket;
  char buffer[8192];
  memset(buffer, '\0',8192);
  char buffer_rec[8192];
  memset(buffer_rec, '\0',8192);
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


   while (1){
	  /*---- Accept call creates a new socket for the incoming connection ----*/
	  addr_size = sizeof serverStorage;
	  newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage, &addr_size);

      recv(newSocket, buffer_rec,8192, 0);
      //printf("%s",
      printf("Tamanho do buffer  %i",sizeof buffer_rec);
	  printf("Data received: %s\n\n",buffer_rec);
	   /*---- Send message to the socket of the incoming connection ----*/
	  strcpy(buffer,"Hello World\n");
	  send(newSocket,buffer,13,0);
	  //close(newSocket);
	}
  return 0;
}

