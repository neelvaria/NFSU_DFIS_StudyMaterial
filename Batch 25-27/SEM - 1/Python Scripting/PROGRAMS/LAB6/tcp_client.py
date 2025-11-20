import socket

class TCPClient:
    def __init__(self, server_host='127.0.0.1', server_port=9999):
        # Initialize with server's host and port details
        self.server_host = server_host
        self.server_port = server_port

    def send(self, message):
        # Create a TCP socket for connecting to server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to the server
            sock.connect((self.server_host, self.server_port))
            # Send the message to the server
            sock.sendall(message.encode())
            # Receive the response from the server
            response = sock.recv(1024).decode()
            print("Received from server:", response)

if __name__ == "__main__":
    # Create client object and send user input to server
    client = TCPClient()
    msg = input("Enter message to send (TCP): ")
    client.send(msg)
