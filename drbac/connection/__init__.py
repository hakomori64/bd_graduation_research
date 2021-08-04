import socket
import base64
import json

# project import
from drbac.config import Config
from drbac.crypto.interfaces.crypto import Crypto
from drbac.crypto.interfaces.public_key_crypto import PublicKeyCrypto
from drbac.crypto.interfaces.common_key_crypto import CommonKeyCrypto


class ConnectionInterface:

  def __init__(self, conn: socket, crypto: Crypto):
    self.__conn = conn
    self.crypto = crypto
  
  def set_crypto(self, crypto: Crypto):
    self.crypto = crypto
  
  def __del__(self):
    if self.__conn is not None:
      self.__conn.close()

  def send(self, data): # send json object

    if isinstance(self.crypto, CommonKeyCrypto):
      cipher_text, tag, nonce = self.crypto.cipher_message(
        bytes(json.dumps(data), encoding='utf-8')
      )
      data = {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8')
      }
    elif isinstance(self.crypto, PublicKeyCrypto):
      # struct data for public key crypto
      pass
    elif self.crypto is None:
      # send raw data
      pass
    
    data = json.dumps(data)
    print(f'sending data... {data}')
    self.__conn.send(bytes(data, encoding='utf-8'))

  def recv(self):
    loaded_data = json.loads(self.__recv_all().decode('utf-8'))

    if isinstance(self.crypto, CommonKeyCrypto):
      loaded_data = json.loads((self.crypto.decipher_message(
        base64.b64decode(loaded_data["cipher_text"]),
        base64.b64decode(loaded_data["tag"]),
        base64.b64decode(loaded_data["nonce"])
      )).decode('utf-8'))
    elif isinstance(self.crypto, PublicKeyCrypto):
      # struct data for public key crypto
      pass
    elif self.crypto is None:
      # return raw data
      pass

    print(f'receiving data: {loaded_data}')
    return loaded_data
  
  def close(self):
    if self.__conn is not None:
      self.__conn.close()
 
  def __recv_all(self):
    buffer_size = Config().BUFFER_SIZE
    full_msg = b''
    while True:
      msg = self.__conn.recv(buffer_size)
      full_msg += msg
      if len(msg) <= buffer_size:
        break
    
    return full_msg
