#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;
#define SHA256_MSG_DIGEST_LEN 32

int binToHexText(unsigned char* bin, size_t binLen, char *hexText)
{
	unsigned int i;

	for (i = 0; i < binLen; i += 1)
	{
		snprintf(hexText + (i * 2), 3, "%02X", *(unsigned char *)&bin[i]);
	}
	return i;
}

int resolveHostname(const char* hostname, struct in_addr* address) 
{
    struct addrinfo *addrInfo;
  
    int ret = getaddrinfo (hostname, NULL, NULL, &addrInfo);
    if (ret == 0) {
        memcpy(address, &((struct sockaddr_in *) addrInfo->ai_addr)->sin_addr, sizeof(struct in_addr));
        freeaddrinfo(addrInfo);
    }
    return ret;
}

int main(int argc, char** argv)
{
    if (argc != 4) {
        printf("usage: %s <ip/hostname> <port> <input> \n", argv[0]);
        return 1;
    }

    const char* serverHostname = argv[1];
    int port = atoi(argv[2]);
    const char* input = argv[3];
    int ret = 0;

    // create client socket
	int clientSocket = socket(PF_INET, SOCK_STREAM, 0);
	if (clientSocket < 0) {
		printf("Cannot create client socket\n");
		return 1;
	}
    
    struct sockaddr_in serverSocketAddress;
    memset (&serverSocketAddress, 0, sizeof(serverSocketAddress));
    serverSocketAddress.sin_family = PF_INET;
    serverSocketAddress.sin_port = htons(port);
    if (resolveHostname(serverHostname, &(serverSocketAddress.sin_addr)) != 0 ) {
        if(inet_pton(serverSocketAddress.sin_family, serverHostname, &(serverSocketAddress.sin_addr)) != 1){
            printf("Cannot determine server address\n");
		    return 1;
        }       
    }

    ret = connect(clientSocket, (struct sockaddr *) &serverSocketAddress, sizeof(serverSocketAddress));
	if (ret != 0) {
		printf("Cannot connect to server\n");
		return 1;
	}
	
    ssize_t written = write(clientSocket, input, strlen(input)+1);
	if (written < 0) {
		printf("Cannot sent data to the server\n");
		return 1;
	}
	
    unsigned char buffer[SHA256_MSG_DIGEST_LEN];
    char hash[SHA256_MSG_DIGEST_LEN * 2+1];

    ssize_t n = read(clientSocket, buffer, SHA256_MSG_DIGEST_LEN);
    if (n < 0) {
		printf("Cannot read data from the server\n");
		return 1;
	}

    binToHexText(buffer, SHA256_MSG_DIGEST_LEN, hash);
    hash[sizeof(hash)] = '\0';
    printf("Server replied with SHA256 hash of '%s': %s\n", input, hash);

    printf("Closing connection\n");
	ret = close(clientSocket);
	if (ret != 0) {
		printf("Cannot close connection\n");
		return 1;
	}

    return ret;
}
