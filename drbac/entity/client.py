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
from drbac.connection.basic_operation import BasicOperationClient
from drbac.connection.crypto_channel import CryptoChannelClient
from drbac.connection.user_auth import AuthClient
from drbac.connection.role_management import RoleManagementClient
from drbac.crypto.diffie_hellman import DiffieHellman


class Client(
  BasicOperationClient,
  CryptoChannelClient,
  AuthClient,
  RoleManagementClient):

  def __init__(self):
    self.conn = None

  def listen_user_input(self):
    while True:
      try:
        query = input('> ')

        if query == 'connect':
          host = input('host: string > ')
          port = int(input('port: int > '))
          self.connect(host, port)
          print('connection established')
        elif query == 'encrypt channel':
          self.initialize_crypto_channel()
          print('connection is encrypted')
        elif query == 'identificate':
          name = input('name: string > ')
          
          #TODO automatically find public/private key
          public_key_path = input('public key path: string > ')
          private_key_path = input('private key path: string > ')

          self.identificate(name, public_key_path, private_key_path)
          print('identification completed')
        elif query == 'delegate role':
          sbj = input('subject: string > ')
          obj = input('object: string > ')
          issuer = input('issuer: string > ')
          self.delegate_role(sbj, obj, issuer)
          print('role delegation complete')
        elif query == 'exit':
          del self.conn
          print('exit program')
          break
        
      except Exception as err:
        print(err)
        print('closing connection')
        if self.conn is not None:
          del self.conn
        break

def main():
  Client().listen_user_input()
