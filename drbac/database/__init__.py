import sqlite3
from drbac.config import Config

class DatabaseConnectionManager:
    def __init__(self):
        self._conn = None
        self.init_database()

    def init_database(self):
        dbname = Config().DB_NAME
        self._conn = sqlite3.connect(dbname)
    
    def create_table(self):

        query = (
            'CREATE TABLE IF NOT EXISTS delegations ('
            'id INTEGER PRIMARY KEY,'
            'subject TEXT,'
            'object TEXT,'
            'issuer TEXT'
            ');'
        )
        self.execute_query(query)
    
    def execute_query(self, query):
        assert self._conn is not None

        cur = self._conn.cursor()
        cur.execute(query)
        self._conn.commit()
        rows = cur.fetchall()

        return rows

    def __del__(self):
        if self._conn is not None:
            self._conn.close()