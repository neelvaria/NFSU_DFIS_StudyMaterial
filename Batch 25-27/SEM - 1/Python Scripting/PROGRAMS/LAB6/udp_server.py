import socket

class UDPServer:
    def __init__(self, host='127.0.0.1', port=9999):
        # Initialize the server with specified host and port
        self.host = host
        self.port = port
        # Create a UDP socket using IPv4
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Bind the socket to host and port for receiving data
        self.server_socket.bind((self.host, self.port))
        print(f"UDP Server listening on {self.host}:{self.port}")

    def run(self):
        # Server loop: continuously listen for client datagrams
        while True:
            # Receive data and the address it came from (client)
            data, addr = self.server_socket.recvfrom(1024)
            print(f"Received from {addr}: {data.decode()}")
            # Send back the received data in uppercase to client
            self.server_socket.sendto(data.upper(), addr)

if __name__ == "__main__":
    # Create and run the UDP server
    server = UDPServer()
    server.run()
