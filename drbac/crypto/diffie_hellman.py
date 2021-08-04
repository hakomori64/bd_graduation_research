import random

from drbac.crypto.aes import AES

class DiffieHellman(AES):

  def __init__(self, g, p):
    self.__generator = g
    self.__prime = p
    self.set_secret_key()

  def set_secret_key(self):
    self.__secret_key = random.randint(0, self.__prime-2)
  
  def get_public_key(self):
    num = 1
    for i in range(self.__secret_key):
      num = (num * self.__generator) % self.__prime
    return num
  
  def key_share(self, opponent_public_key):
    self.key = (opponent_public_key ** self.__secret_key) % self.__prime
  