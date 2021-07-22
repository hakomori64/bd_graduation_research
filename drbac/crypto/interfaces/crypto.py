from abc import ABCMeta, abstractmethod


class Crypto(metaclass=ABCMeta):
    
    @abstractmethod
    def cipher_message(self):
        raise NotImplementedError()
    
    @abstractmethod
    def decipher_message(self):
        raise NotImplementedError()