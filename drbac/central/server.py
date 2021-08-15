import socket
import threading

# project import
from drbac.connection import ConnectionInterface
from drbac.connection.crypto_channel import CryptoChannelServer
from drbac.connection.user_auth import AuthServer
from drbac.connection.role_management import RoleManagementServer
from drbac.database import DatabaseConnectionManager

class ThreadedServer:
    
    def __init__(self, host_info: tuple):
        host, port = host_info
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

        # setting up local space for each thread
        self.local = threading.local()
    
        # initializing database and table
        manager = DatabaseConnectionManager()
        manager.create_table()


    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(300)
            threading.Thread(target = self.listen_to_client, args = (client, address)).start()
    
    def listen_to_client(self, client, address):
        self.local.server = Server(client, address)
        self.local.server.listen()

class Server(
    CryptoChannelServer,
    AuthServer,
    RoleManagementServer,
    ):


    def __init__(self, conn, address):
        self.conn = ConnectionInterface(conn, None)
        self.address = address
        self.handlers = {
            'CRYPTO_CHANNEL_REQ1': self.initialize_crypto_channel,
            'AUTH_IDENTIFICATE_REQ1': self.identificate,
            'WHOAMI_REQ1': self.whoami,
            'DELEGATE_ROLE_REQ1': self.delegate_role,
            'SEARCH_ROLE_REQ1': self.search_role,
        }

        # save client info
        name = None
    
    def listen(self):
        print('connection established')
        while True:
            try:
                data = self.conn.recv()
                if 'type' in data and 'data' in data:
                    req_type = data['type']
                    req_data = data['data']

                    handle_func = self.handlers.get(req_type)
                    if handle_func is not None:
                        handle_func(req_data)
                    else:
                        raise Exception('request_type is not implemented')
                else:
                    raise Exception('invalid json structure')
            except Exception as e:
                print(e)
                print(f'close connection: {self.address}')
                self.conn.close()
                break

def main():
    ThreadedServer(('127.0.0.1', 8080)).listen()