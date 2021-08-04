from drbac.crypto.aes import AES
from drbac.connection import ConnectionInterface
from drbac.database import DatabaseConnectionManager
from drbac.role import RoleRepository

class RoleManagementClient:
    def delegate_role(self, sbj, obj, issuer):

        # assert connection set up
        assert self.conn is not None and isinstance(self.conn, ConnectionInterface)

        # assert user authenticated successfully
        assert isinstance(self.conn.crypto, AES)

        data = {
            'type': 'DELEGATE_ROLE_REQ1',
            'data': {
                'subject': sbj,
                'object': obj,
                'issuer': issuer
            }
        }

        self.conn.send(data)

        data = self.conn.recv()
        if data['type'] == 'DELEGATE_ROLE_RES1_FAILED':
            print('Something went wrong while delegating role')
            return
        
        print('delegation succeeded')


class RoleManagementServer:
    
    def delegate_role(self, data):

        # assert connection is established
        assert self.conn is not None and isinstance(self.conn, ConnectionInterface)

        sbj = data['subject']
        obj = data['object']
        issuer = data['issuer']

        #TODO check user has permission to do the operation

        try:
            RoleRepository.delegate_role(sbj, obj, issuer)
        except Exception as e:
            self.conn.send({
                'type': 'DELEGATE_ROLE_RES1_FAILED',
                'data': {
                    'reason': str(e)
                }
            })
            return
        
        self.conn.send({
            'type': 'DELEGATE_ROLE_RES1_OK',
            'data': data
        })