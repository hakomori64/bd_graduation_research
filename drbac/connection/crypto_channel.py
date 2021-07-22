from drbac.connection import ConnectionInterface
from drbac.config import Config

class CryptoChannelClient:

    def initialize_crypto_channel(self):
        assert self.__conn is not None and isclass(self.__conn, ConnectionInterface)

        g = Config().DIFFIE_HELLMAN_PUBLIC_KEY_G
        p = Config().DIFFIE_HELLMAN_PUBLIC_KEY_P

        dh = DiffieHellman(g, p)

        data = {
            "type": "CRYPTO_CHANNEL_REQ1",
            "data": {
                "public_key": dh.get_public_key(),
            }
        }

        self.__conn.send(data)
        res: dict = self.__conn.recv()

        if "type" not in res or res["type"] != "CRYPTO_CHANNEL_RES1_OK":
            raise Exception('crypto connection could not be published')
            
        
        if "data" not in res:
            raise Exception('Error: no data in the response')
            
        
        if "public_key" not in res["data"]:
            raise Exception('Error: no public key in res data')
        
        public_key = res["data"]["public_key"]
        dh.key_share(public_key)

        self.__conn.set_crypto(dh)


class CryptoChannelServer:

    # mainのスレッドでクライアントから受け取ったデータのタイプが
    # "CRYPTO_CHANNEL_REQ1"だったらこの関数が呼ばれる
    def initialize_crypto_channel(self, data):
        assert self.__conn is not None and isclass(self.__conn, ConnectionInterface)

        g = Config().DIFFIE_HELLMAN_PUBLIC_KEY_G
        p = Config().DIFFIE_HELLMAN_PUBLIC_KEY_P

        dh = DiffieHellman(g, p)

        if "public_key" not in data:
            self.__conn.send({
                "type": "CRYPTO_CHANNEL_RES1_FAILED",
                "data": {
                    "reason": "no public key in data"
                }
            })
            return

        public_key = data["public_key"]
        dh.key_share(public_key)
        self.__conn.set_crypto(dh)
        
        self.__conn.send({
            "type": "CRYPTO_CHANNEL_RES1_OK",
            "data": {
                "public_key": dh.get_public_key()
            }
        })