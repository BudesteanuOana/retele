# Builds the client and the server

all:
	cd ./client_src && $(MAKE)
	cd ./server_src && ${MAKE}

clean:
	cd ./client_src && $(MAKE) clean
	cd ./server_src && ${MAKE} clean
