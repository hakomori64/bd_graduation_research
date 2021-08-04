import re
import os
from Crypto.PublicKey import RSA


def is_valid_actor_format(name):
    regex = '^(([^\\.\\/ ]+)|([^\\/\\. ]+\\.[^\\/\\. ]+))$'
    if re.match(regex, name):
        return True
    else:
        return False

def is_valid_format(actor_type, name):

    regex = ''
    if actor_type == 'entity':
        regex = '^[^\\.\\/ ]+$'
    elif actor_type == 'role' or actor_type == 'user':
        regex = '^[^\\/\\. ]+\\.[^\\/\\. ]+$'

    if re.match(regex, name):
        return True
    else:
        return False

def craft_base_dir(actor_type, name):

    if actor_type == 'entity':
        return f'actors/{name}'
    
    elif actor_type == 'role' or actor_type == 'user':

        return f"actors/{name.replace('.', f'/{actor_type}s/')}"

def generate_key_pair(actor_type, name):

    if not is_valid_actor_format(name):
        raise Exception('invalid name')
    
    if not is_valid_format(actor_type, name):
        raise Exception('invalid format')

    base_dir = craft_base_dir(actor_type, name)
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    private_key = RSA.generate(1024)
    with open(f'{base_dir}/private.pem', 'w+') as f:
        f.write(private_key.export_key().decode('utf-8'))

    public_key = private_key.publickey()
    with open(f'{base_dir}/public.pem', 'w+') as f:
        f.write(public_key.export_key().decode('utf-8'))

def detect_actor_type(name):

    count = 0
    actor_type = ''

    for a_type in ['user', 'role', 'entity']:
        if is_valid_format(a_type, name) and os.path.exists(f"{craft_base_dir(a_type, name)}/public.pem"):
            count += 1
            actor_type = a_type
    
    if count == 0:
        raise Exception('cannot detect actor type(public key does not exist??)')
    elif count > 1:
        raise Exception('cannot detect actor type(name conflict)')
    
    return actor_type