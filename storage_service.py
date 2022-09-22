from tinydb import TinyDB, Query
import sys

STORAGE_LOCATION = 'scans.json'

class Storage_Service:
    def __init__(self):
        self.db = TinyDB(STORAGE_LOCATION, indent=4, separators=(',', ': '))
        
    def add(self, data, scanner = 'ZAP'):
        self.db.insert(data)
        
    def get_by_name(self, scan_name):
        return self.db.get(Query().scan_name == scan_name)

    def get_by_id(self, scan_id):
        return self.db.get(Query().scan_id == scan_id)

    def update_by_name(self, scan_name, data, scanner='ZAP'):
        self.db.update(data, Query().scan_name == scan_name)

    def update_by_id(self, scan_id, data, scanner='ZAP'):
        self.db.update(data, Query().scan_id == scan_id)
    
    
    