import sqlite3
import json 
import zlib
import os

def getConn(idx):    
    # base_dir = "/Bases de Eventos"    
    base_dir = "/home/jvnunes/wazuhTradeIn/Bases de Eventos"    
    os.makedirs(base_dir, exist_ok=True)

    if not idx:
        print("Erro ao conectar ao banco "+ Exception)
        return None
    
    db_path = os.path.join(base_dir, f"{idx}.db")

    try:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        return conn
    except sqlite3.OperationalError as e:
        print(f"Erro ao conectar ao banco: {e}")
        return None
    # return sqlite3.connect(idx + ".db", check_same_thread=False)

def createTables(idx):
    query = '''
            CREATE TABLE IF NOT EXISTS eventos (
                CHAVE   INTEGER PRIMARY KEY AUTOINCREMENT,
                _index  TEXT,
                _id     TEXT,
                _score  INTEGER,
                _source TEXT
            )    
    '''
    try:
        conn = getConn(idx)
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(e)
  
def getData(idx,query):
    try:
        conn = getConn(idx)
        cursor = conn.cursor()      
        
        cursor.execute(query)
        data = cursor.fetchall()
        
        conn.close()
        return data

    except Exception as e:
        print(f'Error getting data: {e}') #print(e)
        return []

def insertSingleEvent(idx,event):
    if retornaEventoPorId(event._id):
        print("Evento já existe")
        return
    
    else:    
        try:    
            conn = getConn(idx)
            cursor = conn.cursor()
            
            cursor.execute("INSERT INTO eventos (_index, _id, _score, _source) VALUES (?,?,?,?)", (event._index, event._id, event._score, json.dumps(event._source)))
            
            conn.commit()
            conn.close()
            
            print("Inserido com sucesso")
            
        except Exception as e:
            print(f'Error inserting data: {e}') #print(e)

def insertData(idx,events):
    try:
        if not isinstance(events, list):
            events = [events]

        conn = getConn(idx)
        cursor = conn.cursor()

        values = [(event['_index'], event['_id'], event['_score'], json.dumps(event['_source'])) for event in events]
        cursor.executemany("INSERT INTO eventos (_index, _id, _score, _source) VALUES (?,?,?,?)", values)

        conn.commit()
        conn.close()

    except Exception as e:
        print(f'Error inserting data: {e}')
 
def retornaEventoPorId(id):
    try:
        return getData(f"SELECT _source FROM eventos WHERE _id = '{id}'").pop()[0]
    except Exception as e:
        print(f'Error getting event: {e}') #print(e)
        return False
    
def retornaIds(idx):
    try:
        dbIds = getData(idx,"SELECT _id FROM eventos")  
        return [i[0] for i in dbIds]
    except Exception as e:
        print(f'Error getting ids: {e}') #print(e)
        return []
    
def retornaNumeroEventos(idx):    
    try:
        return getData(idx,f"SELECT COUNT(*) FROM eventos WHERE _index = '{idx}'").pop()[0]
    except Exception as e:
        print(f'Error getting number of events: {e}')
        return []
