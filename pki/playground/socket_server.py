import socket
import struct
import json
import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import base64
import hashlib
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

host = '127.0.0.1'
port = 8765
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def main():
  sock.bind((host, port))
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.listen()

  while True:
    print("waiting client...")

    connection, address = sock.accept()
    print('client info:', str(address))

    try:
      # 一時的な共通鍵の共有
      g = 2
      p = 0x11717

      dh = diffie_hellman(g, p)
      dh.set_secret_key()

      recvline = recvAll(connection).decode('utf-8')
      data = json.loads(recvline)
      
      request = data["request"]
      if request != "MSG_KEXINIT":
        socket.send(bytes(json.dumps({
          "response": "MSG_KEXINIT_FAILED"
        })), encoding="utf-8")
        connection.close()
        continue
      
      name = data["name"]
      public_key = data["public_key"]

      dh.key_share(public_key)

      data = {
        "response": "MSG_KEXINIT_RESPONSE",
        "public_key": dh.get_public_key()
      }

      print("dumping data...")
      data = json.dumps(data)

      print("sending response data to server...")
      connection.send(bytes(data, encoding="utf-8"))

      ci = ConnectionInterface(connection, dh)

      print("key sharing completed")

      # ユーザーから名前、公開鍵のblobを受けとる
      
      data = ci.recv()
      # リクエスト名が合っているか検証
      request = data['request']
      if request != 'MSG_USERAUTH_REQUEST':
        ci.send({
          'response': 'MSG_USERAUTH_FAILED',
          'reason': 'invalid request name'
        })
        continue
      # nameが変わっていないか検証
      auth_name = data['name']
      if name != auth_name:
        ci.send({
          'response': 'MSG_USERAUTH_FAILED',
          'reason': 'auth name has changed'
        })
        connection.close()
        continue
      
      # pubkey_blobが合っているかを検証
      pubkey_blob = data['pubkey_blob']
      # TODO パスをユーザー名を使って変える
      f = open("playground/public.pem", "r")
      public_key = RSA.import_key(f.read())
      f.close()
      fingerprint = hashlib.md5(public_key.export_key('DER')).hexdigest()
      if pubkey_blob != fingerprint:
        ci.send({
          "response": "MSG_USERAUTH_FAILED",
          "reason": "invalid public key"
        })
        connection.close()
        continue
      
      # ユーザーから送られてきた公開鍵は正しい
      # 
      ci.send({
        'response': "MSG_USERAUTH_PK_OK"
      })

      data = ci.recv()
      request = data['request']
      if request != 'MSG_USERAUTH_REQUEST':
        ci.send({
          'response': 'MSG_USERAUTH_FAILED',
          'reason': 'Invalid Request'
        })
        connection.close()
        continue
      third_name = data['name']
      if third_name != name:
        ci.send({
          'response': 'MSG_USERAUTH_FAILED',
          'reason': 'Invalid user'
        })
        connection.close()
        continue

      signature = base64.b64decode(data['signature'])
      print('signature', signature)
      with open('playground/public.pem', 'br') as f:
        public_pem = f.read()
        public_key = RSA.import_key(public_pem)
      
      signature_data = {
        'name': name,
        'pubkey_blob': fingerprint
      }
      h = SHA256.new(json.dumps(signature_data).encode('utf-8'))
      try:
        pkcs1_15.new(public_key).verify(h, signature)
      except ValueError:
        ci.send({
          'response': 'MSG_USERAUTH_FAILED',
          'reason': 'Invalid private key'
        })
      
      # ユーザー認証が完了したので共通鍵を作成して
      # 以降それを利用して通信する
      key = random.randint(0, 100000000)
      ci.send({
        'response': 'MSG_USERAUTH_PK_OK',
        'common_key': key
      })

      commonKeyEncDec = CommonKeyEncDec(key)
      ci = ConnectionInterface(connection, commonKeyEncDec)

      print(ci.recv())

      ci.send({'message': 'hi'})

    finally:
      connection.close()

  socket.close()

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
    except ValueError:
      raise ValueError; 
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