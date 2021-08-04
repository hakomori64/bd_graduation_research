import os

from drbac.database import DatabaseConnectionManager
from drbac.pki import is_valid_actor_format, is_valid_format, detect_actor_type

class RoleRepository:

    @staticmethod
    def delegate_role(sbj, obj, issuer):

        sbj_type = detect_actor_type(sbj)
        obj_type = detect_actor_type(obj)
        issuer_type = detect_actor_type(issuer)

        if sbj_type not in ['entity', 'user', 'role']:
            raise Exception('invalid subject type')
        if obj_type not in ['role']:
            raise Exception('invalid object type')
        if issuer_type not in ['entity', 'user', 'role']:
            raise Exception('invalid issuer type')

        DatabaseConnectionManager().execute_query(
            "INSERT INTO delegations (subject, object, issuer) "
            f'VALUES("{sbj}", "{obj}", "{issuer}");'
        )