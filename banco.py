import sqlite3

def getConn():
    return sqlite3.connect("eventos.db")

def createTables():
    query = '''
            CREATE TABLE IF NOT EXISTS eventos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dados TEXT NOT NULL,
                selecionado BOOLEAN DEFAULT 0
            )    
    '''
    
def closeDb(cursor,conn):
    
    cursor.execute("VACUUM")
    conn.commit()
    conn.close()