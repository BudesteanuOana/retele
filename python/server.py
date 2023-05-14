import socket
import hashlib

LOCALHOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 8888  # Port to listen on

def calculateHash(input):
    context = hashlib.sha256()
    context.update(input)
    return context.digest()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((LOCALHOST, PORT))
        server.listen()
        print("Server listening on port {0}".format(PORT))
        while True:
            connection, address = server.accept()
            with connection:
                print("Connected by {0}".format(address))
                while True:
                    data = connection.recv(1024)
                    if not data:
                        break
                    digest = calculateHash(data)
                    connection.sendall(digest)

if __name__ == "__main__":
    main()