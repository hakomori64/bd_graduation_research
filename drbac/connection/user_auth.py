from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import hashlib
import json
import base64
import random

# project import 
from drbac.connection import ConnectionInterface
from drbac.crypto.aes import AES
from drbac.pki import is_valid_actor_format

class AuthClient:

    def identificate(self, name):
        assert self.conn is not None and isinstance(self.conn, ConnectionInterface)

        """
        args:
            name: name of entity/user e.g. EntityA.User, EntityA
            public_key_path: public_key to prove user is user
            private_key_path: private_key to prove user is user
        """

        if not is_valid_actor_format(name):
            raise Exception('invalid name format')

        base_dir = f'actors/{name.replace(".", "/users/")}'

        f = open(f'{base_dir}/public.pem', 'r')
        public_key = RSA.import_key(f.read())
        f.close()

        fingerprint = hashlib.md5(public_key.export_key('DER')).hexdigest()

        data = {
            'type': 'AUTH_IDENTIFICATE_REQ1',
            'data': {
                'name': name,
                'public_key_blob': fingerprint,
            }
        }

        self.conn.send(data)

        data = self.conn.recv()
        if data['type'] == 'AUTH_IDENTIFICATE_RES1_FAILED':
            print('blob key may not be registered')
            print(data['data']['reason'])
            return
        
        signature_data = {
            'name': name,
            'public_key_blob': fingerprint
        }
        f = open(f'{base_dir}/private.pem', 'br')
        private_pem = f.read()
        private_key = RSA.import_key(private_pem)
        f.close()

        h = SHA256.new(json.dumps(signature_data).encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(h)

        data = {
            'type': 'AUTH_IDENTIFICATE_REQ2',
            'data': {
                'name': name,
                'signature': base64.b64encode(signature).decode('utf-8')
            }
        }
        self.conn.send(data)

        data = self.conn.recv()
        if data['type'] == 'AUTH_IDENTIFICATE_RES2_FAILED':
            print('blob key may not be registered')
            print(data['data']['reason'])
            return

        aes = AES(data['data']['common_key'])
        self.conn.set_crypto(aes)
    
    def whoami(self):

        self.conn.send({
            'type': 'WHOAMI_REQ1',
            'data': {}
        })

        data = self.conn.recv()
        print(data['data']['name'])

class AuthServer:

    # typeがAUTH_IDENTIFICATE_REQ1だった場合、dataが渡されてこの関数が呼び出される
    def identificate(self, data):
        assert self.conn is not None and isinstance(self.conn, ConnectionInterface)

        name = data['name']
        public_key_blob = data['public_key_blob']

        if not is_valid_actor_format(name):
            self.conn.send({
                "type": "AUTH_IDENTIFICATE_RES1_FAILED",
                "data": {
                    "reason": "invalid name format"
                }
            })
            return
        
        base_dir = f'actors/{name.replace(".", "/users/")}'
        f = open(f'{base_dir}/public.pem', 'r')
        public_key = RSA.import_key(f.read())
        f.close()
        fingerprint = hashlib.md5(public_key.export_key('DER')).hexdigest()
        if public_key_blob != fingerprint:
            self.conn.send({
                "type": "AUTH_IDENTIFICATE_RES1_FAILED",
                "data": {
                    "reason": "invalid public key"
                }
            })
            return
        
        self.conn.send({
            "type": "AUTH_IDENTIFICATE_RES1_OK",
            "data": {}
        })

        data = self.conn.recv()
        request_type = data['type']
        if request_type != 'AUTH_IDENTIFICATE_REQ2':
            self.conn.send({
                "type": "AUTH_IDENTIFICATE_RES2_FAILED",
                "data": {
                    "reason": "invalid request type"
                }
            })
            return
        
        request_name = data['data']['name']
        if request_name != name:
            self.conn.send({
                "type": "AUTH_IDENTIFICATE_RES2_FAILED",
                "data": {
                    "reason": "invalid name"
                }
            })
            return
        
        signature = base64.b64decode(data['data']['signature'])
        signature_data = {
            'name': name,
            'public_key_blob': fingerprint
        }
        h = SHA256.new(json.dumps(signature_data).encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(h, signature)
        except ValueError:
            self.conn.send({
                "type": "AUTH_IDENTIFICATE_RES2_FAILED",
                "data": {
                    "reason": "invalid signature or private key"
                }
            })
            return
        
        # save client name
        self.name = name

        key = random.randint(0, 100000000)
        self.conn.send({
            "type": "AUTH_IDENTIFICATE_RES2_OK",
            "data": {
                "common_key": key
            }
        })

        aes = AES(key)
        self.conn.set_crypto(aes)

    def whoami(self, data):

        self.conn.send({
            'type': 'WHOAMI_RES1',
            'data': {
                'name': self.name
            }
        })