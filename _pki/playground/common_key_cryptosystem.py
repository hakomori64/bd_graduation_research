from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)

message = "message"
ciphertext, tag = cipher.encrypt_and_digest(message.encode())

# ciphertext, tag, cipher.nonceを送信
# どれか一つでも改竄されると検知できる
a = 'a'.encode('utf-8')
key_sent = key 
ciphertext_sent = ciphertext
tag_sent = tag
nonce_sent = cipher.nonce

try:
  cipher_dec = AES.new(key_sent, AES.MODE_EAX, nonce_sent)
  data = cipher_dec.decrypt_and_verify(ciphertext_sent, tag_sent)
except ValueError:
  print("not valid data")
