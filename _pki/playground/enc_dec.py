from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

with open('private.pem', 'br') as f:
  private_pem = f.read()
  private_key = RSA.import_key(private_pem)

with open('public.pem', 'br') as f:
  public_pem = f.read()
  public_key = RSA.import_key(public_pem)


message = "test message"
print("message", message)
public_cipher = PKCS1_OAEP.new(public_key)
ciphertext = public_cipher.encrypt(message.encode())

print("ciphertext", ciphertext)

private_cipher = PKCS1_OAEP.new(private_key)
message2 = private_cipher.decrypt(ciphertext).decode('utf-8')

print('decrypted', message2)
