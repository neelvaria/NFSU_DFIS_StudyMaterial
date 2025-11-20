import socket

class TCPServer:
    def __init__(self, host='127.0.0.1', port=9999):
        # Initialize the server with host and port
        self.host = host
        self.port = port
        # Create a TCP socket using IPv4 addressing
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to the given host and port
        self.server_socket.bind((self.host, self.port))
        # Start listening for incoming connection requests (1 client at a time)
        self.server_socket.listen(1)
        print(f"TCP Server listening on {self.host}:{self.port}")

    def run(self):
        # Start the main loop to accept and handle client connections
        while True:
            # Accept a new client connection
            client_socket, addr = self.server_socket.accept()
            print(f"Connected by {addr}")
            # Receive up to 1024 bytes from the client
            data = client_socket.recv(1024).decode()
            print("Received:", data)
            # Send back the data in uppercase as a response
            client_socket.sendall(data.upper().encode())
            # Close the client socket after handling the request
            client_socket.close()

if __name__ == "__main__":
    # Create the server object and start it
    server = TCPServer()
    server.run()
