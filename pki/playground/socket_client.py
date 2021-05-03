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

PORT = 8765
BUFFER_SIZE = 1024

'''
MSG_KEXINIT          40
MSG_USERAUTH_REQUEST 50
MSG_USERAUTH_FAILURE 51
MSG_USERAUTH_SUCCESS 52
MSG_USERAUTH_BANNER  53
'''

def main():
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    # 接続する
    sock.connect(('127.0.0.1', PORT))
    g = 2
    p = 0x11717

    print("initializing diffie helman...")
    dh = diffie_hellman(g, p)
    dh.set_secret_key()
    print("setup completed")
    # 通信を開始したいとの申し出

    data = {
      "request": "MSG_KEXINIT",
      "name": "cl0wn",
      "public_key": dh.get_public_key(),
    }

    print("dumping data...")
    data = json.dumps(data)

    print("sending request data to server...")
    sock.send(bytes(data, encoding="utf-8"))

    data = json.loads(recvAll(sock).decode("utf-8"))
    
    if data["response"] != "MSG_KEXINIT_RESPONSE":
      print("connection could'nt be published")
      sock.close()
      return
    
    public_key = data["public_key"]
    dh.key_share(public_key)

    ci = ConnectionInterface(sock, dh)
    
    print("key sharing completed")

    print("constructing user auth info...")
    # TODO パスをユーザー名を使って変える
    f = open("playground/public.pem", "r")
    public_key = RSA.import_key(f.read())
    f.close()
    fingerprint = hashlib.md5(public_key.export_key('DER')).hexdigest()

    data = {
      "request": "MSG_USERAUTH_REQUEST",
      "name": "cl0wn",
      "pubkey_blob": fingerprint
    }

    print("sending userauth data to server...")
    ci.send(data)

    data = ci.recv()
    if data['response'] != "MSG_USERAUTH_PK_OK":
      print("user auth failed")
      print(data["reason"] if data.has_key("reason") else "something went wrong")
      return
    
    signature_data = {
      'name': 'cl0wn',
      'pubkey_blob': fingerprint
    }
    with open('playground/private.pem', 'br') as f:
      private_pem = f.read()
      private_key = RSA.import_key(private_pem)
    
    h = SHA256.new(json.dumps(signature_data).encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(h)

    data = {
      'request': 'MSG_USERAUTH_REQUEST',
      'name': 'cl0wn',
      'signature': base64.b64encode(signature).decode('utf-8')
    }
    ci.send(data)

    data = ci.recv()
    commonKeyEncDec = CommonKeyEncDec(data['common_key'])
    ci = ConnectionInterface(sock, commonKeyEncDec)

    ci.send({'message': 'hello'})

    print(ci.recv())
    

def recvAll(sock):
  full_msg = b''
  while True:
    msg = sock.recv(4096)
    full_msg += msg
    if len(msg) <= 4096:
      break
  
  return full_msg

class diffie_hellman():
  def __init__(self, generator, prime):
    self.__generator = generator
    self.__prime = prime

  def set_secret_key(self):
    self.__secret_key = random.randint(0, self.__prime-2)
  
  def get_public_key(self):
    num = 1
    for i in range(self.__secret_key):
      num = (num * self.__generator) % self.__prime
    return num
  
  def key_share(self, opponent_public_key):
    self.__key = (opponent_public_key ** self.__secret_key) % self.__prime
  
  def cipher_message(self, plain_message: bytes):
    key = self.__key.to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(plain_message)
    return ciphertext, tag, cipher.nonce
  
  def decipher_message(self, secret_message: bytes, tag, nonce):
    key = self.__key.to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = b''
    try:
      data = cipher.decrypt_and_verify(secret_message, tag)
    finally:
      return data

class CommonKeyEncDec:
  def __init__(self, key):
    self.__key = key
  
  def cipher_message(self, plain_message: bytes):
    key = self.__key.to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(plain_message)
    return ciphertext, tag, cipher.nonce

  def decipher_message(self, secret_message: bytes, tag, nonce):
    key = self.__key.to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = b''
    try:
      data = cipher.decrypt_and_verify(secret_message, tag)
    finally:
      return data

class ConnectionInterface:
  def __init__(self, conn, encdec):
    self.__conn = conn
    self.__encdec = encdec
  
  def send(self, data): # send json object
    dumped_data = json.dumps(data)
    cipher_text, tag, nonce = self.__encdec.cipher_message(
      bytes(dumped_data, encoding='utf-8')
    )
    data = {
      'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
      'tag': base64.b64encode(tag).decode('utf-8'),
      'nonce': base64.b64encode(nonce).decode('utf-8')
    }
    data = json.dumps(data)
    self.__conn.send(bytes(data, encoding='utf-8'))

  def recv(self):
    data = json.loads(recvAll(self.__conn).decode('utf-8'))
    data = (self.__encdec.decipher_message(
      base64.b64decode(data["cipher_text"]),
      base64.b64decode(data["tag"]),
      base64.b64decode(data["nonce"])
    )).decode('utf-8')

    return json.loads(data)

if __name__ == '__main__':
  main()