import socket
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import json
import random
import base64
import hashlib
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import os
from dotenv import load_dotenv

# project import
from drbac.config import Config
from drbac.connection import ConnectionInterface
from drbac.connection.crypto_channel import CryptoChannelClient
from drbac.crypto.diffie_hellman import DiffieHellman

class Client(CryptoChannelClient):

  def __init__(self):
    self.__conn = None
  
  def connect(self, host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    self.__conn = ConnectionInterface(sock, None)

    self.initialize_crypto_channel() # from CryptoChannelClient

if __name__ == '__main__':
  # TODO initialize client
  print('This is client main program')