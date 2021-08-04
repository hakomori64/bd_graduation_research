from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

with open('private.pem', 'br') as f:
  private_pem = f.read()
  private_key = RSA.import_key(private_pem)

with open('public.pem', 'br') as f:
  public_pem = f.read()
  public_key = RSA.import_key(public_pem)


message1 = "test message"
h1 = SHA256.new(message1.encode()) # messageをハッシュして秘密鍵で暗号化
signature = pkcs1_15.new(private_key).sign(h1)

message2 = "test message"
h2 = SHA256.new(message2.encode())
try:
  pkcs1_15.new(public_key).verify(h2, signature) # messageが改竄されていないかを確認する
  verified = True
except ValueError:
  verified = False

print(verified)
