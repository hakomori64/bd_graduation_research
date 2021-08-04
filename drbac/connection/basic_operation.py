import socket

# project
from drbac.connection import ConnectionInterface

class BasicOperationClient:

    def connect(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    
        self.conn = ConnectionInterface(sock, None)
    
    def close(self):
        if self.conn is not None:
            del self.conn