#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define LOCALHOST "127.0.0.1"
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define SERVER_QUEUE 10

/* 
    function that calculates SHA256 hash of the given input 
    returns 0 for success, -1 for error.
*/
int calculateSha256Hash(const char* input, size_t inputLen, unsigned char* output, int outputBufferLen){
    if (outputBufferLen < SHA256_DIGEST_LENGTH){
        printf("Buffer is too small for calculating hash\n");
        return -1;
    }
    int ret = 0;
    SHA256_CTX hashCtx;
    // the next 3 functions return 0 for error and 1 for success.
    // see https://www.openssl.org/docs/man1.1.1/man3/SHA256.html
    ret = SHA256_Init(&hashCtx);
    ret = SHA256_Update(&hashCtx, input, inputLen);
    ret = SHA256_Final(output, &hashCtx);
    if (ret == 1){
        // our function return 0 for success
        return 0;
    } else {
        return -1;
    }
}

/* perform AES ECB encryption on the given input using the given key */
int aesEcbEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;
	int ret = 0;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
		printf("Can't create cipher context");
	    EVP_CIPHER_CTX_free(ctx);
		return 1;
	}

    /*
     * Initialise the encryption operation.
     * In this example we are using 256 bit AES (i.e. a 256 bit key).
	 * The key used is the hash of the input.
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)){
		printf("Can't init cipher operation");
	    EVP_CIPHER_CTX_free(ctx);
		return 1;
	}

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
		printf("Can't perform cipher operation");
	    EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
		printf("Can't perform cipher operation");
	    EVP_CIPHER_CTX_free(ctx);
		return 1;
	}
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*
    function used for reading input from incoming client connections
    and processing that input (calls calculateSha256Hash to provide
    SHA256 hash of the client input)
*/
int process_request(int clientSocket) {
	char buffer[BUFFER_SIZE];
	unsigned char outBuffer[BUFFER_SIZE];
	ssize_t n, cipherTextLen;
    int ret = 0;
	while (true) {
        memset(buffer, 0, BUFFER_SIZE);
		n = read(clientSocket, &buffer, sizeof(buffer)-1);
		if (n < 0) {
			printf("Error while reading from client %d\n", clientSocket);
			return 1;
		}
		if (n == 0) {
			break;
		}

		printf("Received from clinet %d: %s\n", clientSocket,  buffer);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        memset(hash, 0xFF, SHA256_DIGEST_LENGTH);
        ret = calculateSha256Hash(buffer, n, hash, SHA256_DIGEST_LENGTH);
		cipherTextLen = aesEcbEncrypt((unsigned char*) buffer, n, hash, outBuffer);
        if (send(clientSocket, outBuffer, cipherTextLen, NULL) < 0) {
            ret = 1;
		    printf("Error sending hash to client %d\n", clientSocket);
        }
	}

	printf("Closing connection with client %d\n", clientSocket);

	if (close(clientSocket) != 0){
        ret = 1;
		printf("Error while closing connection with client %d\n", clientSocket);
	}
	return ret;
}

int main() {
	int serverSocket = socket(PF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0) {
		printf("Error creating server socket\n");
		return 1;
	}

	struct sockaddr_in serverSocketAddr;
	serverSocketAddr.sin_family = PF_INET;
	serverSocketAddr.sin_port = htons(SERVER_PORT);

	if (!inet_pton(PF_INET, LOCALHOST, &serverSocketAddr.sin_addr)) {
		printf("Error parsing server internet address\n");
		return 1;
	}

	int ret = 0;
    
    ret = bind(serverSocket, (struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr));
	if (ret != 0) {
		printf("Error binding server socket\n");
		return 1;
	}

	ret = listen(serverSocket, SERVER_QUEUE);
	if (ret != 0) {
		printf("Error while trying to listen\n");
		return 1;
	}

	printf("Server listening on port %d\n", SERVER_PORT);

	int clientSocket;
	struct sockaddr_in clientSocketAddr;
	socklen_t clientSocketAddrLen;
	while (true) {
		clientSocket = accept(serverSocket, (struct sockaddr *) &clientSocketAddr, &clientSocketAddrLen);
		if (clientSocket < 0) {
			printf("Error while accepting client connection\n");
			return 1;
		}

        ret = process_request(clientSocket);
        if (ret != 0){
            // just return. Error message will pe provided by process_request call.
		    return ret;
        }
	}
}