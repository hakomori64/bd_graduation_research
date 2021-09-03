import os

from drbac.database import DatabaseConnectionManager
from drbac.pki import is_valid_actor_format, is_valid_format, detect_actor_type, get_entity

class RoleRepository:

    @staticmethod
    def validate_delegation(sbj, obj, issuer, name):

        if issuer != name:
            # 付与の発行者(issuer)は、現在通信認証が済んでいるユーザー名と一致する
            raise Exception('issuer name mismatch')
        
        sbj_type = detect_actor_type(sbj)
        obj_type = detect_actor_type(obj)
        issuer_type = detect_actor_type(issuer)

        if sbj_type not in ['entity', 'user', 'role']:
            raise Exception('invalid subject type')
        if obj_type not in ['role']:
            raise Exception('invalid object type')
        if issuer_type not in ['entity', 'user', 'role']:
            raise Exception('invalid issuer type')
        
        # [EntityB -> EntityA.RoleA] EntityA.User
        
        # issuerがEntityであり、自分の名前空間に属するロールを配布するならOK
        if issuer_type == 'entity' and get_entity(obj) == issuer:
            return
        
        obj_name = obj.split("`")[0]
        roles = RoleRepository.search_role(issuer)
        # issuerがロールの付与権限を持っていたら認める
        if f"{obj_name}`" in roles:
            # TODO assignment delegationの判別方法を`じゃなくて別のものにしたほうがいいかも？
            return
        
        # ロールを付与する権限を持っていない
        raise Exception('insufficient permission')


    @staticmethod
    def delegate_role(sbj, obj, issuer):

        DatabaseConnectionManager().execute_query(
            "INSERT INTO delegations (subject, object, issuer) "
            f'VALUES("{sbj}", "{obj}", "{issuer}");'
        )
    
    @staticmethod
    def search_role(name):
        name_type = detect_actor_type(name)

        if name_type not in ['entity', 'user']:
            raise Exception('invalid name format. It must be entity')
        
        roles = DatabaseConnectionManager().execute_query(
            "SELECT object FROM delegations "
            f'WHERE subject = "{name}"'
        )

        return list(map(lambda element: element[0], roles))