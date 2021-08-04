from Crypto.Cipher import AES as CryptoAES
from drbac.crypto.interfaces.common_key_crypto import CommonKeyCrypto


class AES(CommonKeyCrypto):

  def __init__(self, key):
    self.key = key
  
  def cipher_message(self, plain_message: bytes):
    assert self.key is not None

    key = self.key.to_bytes(16, 'big')
    cipher = CryptoAES.new(key, CryptoAES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(plain_message)
    return ciphertext, tag, cipher.nonce

  def decipher_message(self, secret_message: bytes, tag, nonce):
    assert self.key is not None

    key = self.key.to_bytes(16, 'big')
    cipher = CryptoAES.new(key, CryptoAES.MODE_EAX, nonce)
    data = b''
    try:
      data = cipher.decrypt_and_verify(secret_message, tag)
    finally:
      return data