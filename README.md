# retele
Client server implementation over TCP.

Client sends a string from command line and the server will respond with the AES ECB ciphertext.
The key used for encrypting the input is the SHA256 hash of the input.

To start the server:
	`./server`
Server will start listening on port 8080

Example to start client:
	`./client localhost 8080 "hello world"`