import socket
import sys

def main(argc, argv):
    if argc < 4:
        print("usage: {0} <ip/hostname> <port> <input> \n".format(argv[0]))

    hostname = argv[1]
    port = 0
    try:
        port = int(argv[2])
    except ValueError:
        print("Error: Invalid value for port parameter")
        return
    input_data = argv[3]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((hostname, port))
        s.sendall(bytes(input_data, 'utf-8'))
        data = s.recv(1024)
        print("Received {0}".format(data.hex()))

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)