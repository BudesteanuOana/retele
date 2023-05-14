Client server implementation over TCP.

client sends a string from command line and the server will respond with the SHA256 hash of that string.

To start server:
	`python3 server.py`
Server will start listening on port 8888

Example to start client:
	`python3 client.py localhost 8888 "hello world"`
