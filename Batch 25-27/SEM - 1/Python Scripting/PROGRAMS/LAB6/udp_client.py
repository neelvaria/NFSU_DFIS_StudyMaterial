import socket

class UDPClient:
    def __init__(self, server_host='127.0.0.1', server_port=9999):
        # Initialize with server's host and port configuration
        self.server_host = server_host
        self.server_port = server_port

    def send(self, message):
        # Create a UDP socket for sending/receiving datagrams
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Send the encoded message to the server's address
            sock.sendto(message.encode(), (self.server_host, self.server_port))
            # Wait for and receive the response from server
            response, _ = sock.recvfrom(1024)
            print("Received from server:", response.decode())

if __name__ == "__main__":
    # Create the client and send user input as a message
    client = UDPClient()
    msg = input("Enter message to send (UDP): ")
    client.send(msg)
