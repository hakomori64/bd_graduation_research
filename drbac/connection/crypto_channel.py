from drbac.connection import ConnectionInterface
from drbac.config import Config
from drbac.crypto.diffie_hellman import DiffieHellman

class CryptoChannelClient:

    def initialize_crypto_channel(self):
        assert self.conn is not None and isinstance(self.conn, ConnectionInterface)

        g = Config().DIFFIE_HELLMAN_PUBLIC_KEY_G
        p = Config().DIFFIE_HELLMAN_PUBLIC_KEY_P

        dh = DiffieHellman(g, p)

        data = {
            "type": "CRYPTO_CHANNEL_REQ1",
            "data": {
                "public_key": dh.get_public_key(),
            }
        }

        print(f'now sending data {data}')
        self.conn.send(data)
        res: dict = self.conn.recv()
        print(f'res: {res}')

        if "type" not in res or res["type"] != "CRYPTO_CHANNEL_RES1_OK":
            raise Exception('crypto connection could not be published')
            
        
        if "data" not in res:
            raise Exception('Error: no data in the response')
            
        
        if "public_key" not in res["data"]:
            raise Exception('Error: no public key in res data')
        
        public_key = res["data"]["public_key"]
        dh.key_share(public_key)

        self.conn.set_crypto(dh)

        try:
            self.conn.send({
                "type": "CRYPTO_CHANNEL_REQ2",
                "data": {
                    "ping": "ping"
                }
            })

            data = self.conn.recv()
            if data["type"] != "CRYPTO_CHANNEL_RES2_OK":
                raise Exception('encryption failed')

        except Exception as e:
            print(e)



class CryptoChannelServer:

    # mainのスレッドでクライアントから受け取ったデータのタイプが
    # "CRYPTO_CHANNEL_REQ1"だったらこの関数が呼ばれる
    def initialize_crypto_channel(self, data):
        assert self.conn is not None and isinstance(self.conn, ConnectionInterface)

        g = Config().DIFFIE_HELLMAN_PUBLIC_KEY_G
        p = Config().DIFFIE_HELLMAN_PUBLIC_KEY_P

        dh = DiffieHellman(g, p)

        if "public_key" not in data:
            self.conn.send({
                "type": "CRYPTO_CHANNEL_RES1_FAILED",
                "data": {
                    "reason": "no public key in data"
                }
            })
            return

        public_key = data["public_key"]
        dh.key_share(public_key)
        
        self.conn.send({
            "type": "CRYPTO_CHANNEL_RES1_OK",
            "data": {
                "public_key": dh.get_public_key()
            }
        })

        self.conn.set_crypto(dh)

        try:
            data = self.conn.recv()
            if data["type"] != "CRYPTO_CHANNEL_REQ2":
                self.conn.send({
                    "type": "CRYPTO_CHANNEL_RES2_FAILED",
                    "data": {
                        "invalid request. expected ping"
                    }
                })
                return

            self.conn.send({
                "type": "CRYPTO_CHANNEL_RES2_OK",
                "data": {
                    "ping": "data received"
                }
            })
        except Exception as e:
            print(e)