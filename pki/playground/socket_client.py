import socket
import struct
from Crypto.Cipher import AES

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
    
    # 通信を開始したいとの申し出
    g = 50
    data = b'\x40'
    data = b''
    

    data = b'\x50' # USERAUTH_REQUEST
    data += 'cl0wn'.encode('utf-8')
    data += 'ssh-userauth'.encode('utf-8')
    data += 'publickey'.encode('utf-8')
    data += ''

    sock.send("HI\nI'm yu.".encode('utf-8'))

    recvline = recvAll(sock)
    print(recvline)
    print()

    sock.send("How Are you".encode('utf-8'))

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
    self.__secret_key = random.randInt(0, self.__prime-2)
  
  def get_public_key(self):
    return (self.__generator ** self.__secret_key) % self.__prime
  
  def key_share(self, dh):
    self.__key = (dh.get_public_key() ** self.__secret_key) % self.__prime
  
  def cipher_message(self, plain_message: bytes):
    key = self.__key.to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(plain_message)
    return ciphertext, tag
  
  def decipher_message(self, secret_message: bytes, tag, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = b''
    try:
      data = cipher.decrypt_and_verify(secret_message, tag)
    finally:
      return data


if __name__ == '__main__':
  main()