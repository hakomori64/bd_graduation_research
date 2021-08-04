import re
import os
from Crypto.PublicKey import RSA


def is_valid_actor_format(name):
    regex = '^(([^\\.\\/ ]+)|([^\\/\\. ]+\\.[^\\/\\. ]+))$'
    if re.match(regex, name):
        return True
    else:
        return False


def generate_key_pair(name):

    if not is_valid_actor_format(name):
        raise Exception('invalid name')

    name = name.replace('.', '/')
    base_dir = f'actors/{name}'
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    private_key = RSA.generate(1024)
    with open(f'{base_dir}/private.pem', 'w+') as f:
        f.write(private_key.export_key().decode('utf-8'))

    public_key = private_key.publickey()
    with open(f'{base_dir}/public.pem', 'w+') as f:
        f.write(public_key.export_key().decode('utf-8'))
