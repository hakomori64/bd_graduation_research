from dotenv import load_dotenv
import os

class Config(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls, *args, **kwargs)
            
            # load environment variables
            cls._load_variables()

        return cls._instance
    
    @classmethod
    def _load_variables(cls):
        load_dotenv()

        try:
            # server / entity settings
            cls._instance.CENTRAL_SERVER_HOST = os.environ['CENTRAL_SERVER_HOST']
            cls._instance.CENTRAL_SERVER_PORT = int(os.environ['CENTRAL_SERVER_PORT'])
            cls._instance.ENTITY_SERVER_PORT = int(os.environ['ENTITY_SERVER_PORT'])

            # buffer size for command/data packat
            cls._instance.BUFFER_SIZE = int(os.environ['BUFFER_SIZE'])

            # diffie hellman public keys
            cls._instance.DIFFIE_HELLMAN_PUBLIC_KEY_G = int(os.environ['DIFFIE_HELLMAN_PUBLIC_KEY_G'])
            cls._instance.DIFFIE_HELLMAN_PUBLIC_KEY_P = int(os.environ['DIFFIE_HELLMAN_PUBLIC_KEY_P'])

            # database settings
            cls._instance.DB_NAME = os.environ['DB_NAME']

        except KeyError as err:
            print('environment variables should be set correctly')