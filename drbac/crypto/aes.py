from drbac.crypto.interfaces.common_key_crypto import CommonKeyCrypto


class AES(CommonKeyCrypto):

  def __init__(self, key):
    self.__key = key
  
  def cipher_message(self, plain_message: bytes):
    assert self.__key is not None

    key = self.__key.to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(plain_message)
    return ciphertext, tag, cipher.nonce

  def decipher_message(self, secret_message: bytes, tag, nonce):
    assert self.__key is not None

    key = self.__key.to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = b''
    try:
      data = cipher.decrypt_and_verify(secret_message, tag)
    finally:
      return data