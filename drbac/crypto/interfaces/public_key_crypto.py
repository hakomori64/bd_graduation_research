from abc import abstractmethod
from drbac.crypto.interfaces.crypto import Crypto

class PublicKeyCrypto(Crypto):
    
    @abstractmethod
    def cipher_message(self, plain_message: bytes):
        """
        args:
            plain_message: message to be encrypted
        returns:
            secret_message: encrypted message
            kwargs: this property will be different for each class
        """
        raise NotImplementedError()
    
    @abstractmethod
    def decipher_message(self, secret_message: bytes, **kwargs):
        """
        args:
            secret_message: encrypted message
            kwargs: this property will be different for each class
        returns:
            plain_message: message to be encrypted
        """
        raise NotImplementedError()