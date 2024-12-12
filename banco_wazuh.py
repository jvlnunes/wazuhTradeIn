import sqlite3
import json 

# teste

def getConn(idx):    
    return sqlite3.connect(idx + ".db", check_same_thread=False) if idx else sqlite3.connect("EventosWazuhAlerts.db")

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
        print(e)
        return []

def insertSingleEvent(idx,event):
    if retornaEventoPorId(event._id):
        print("Evento já existe")
        return
    
    else:        
        conn = getConn(idx)
        cursor = conn.cursor()
        
        cursor.execute("INSERT INTO eventos (_index, _id, _score, _source) VALUES (?,?,?,?)", (event._index, event._id, event._score, json.dumps(event._source)))
        
        conn.commit()
        conn.close()
        
        print("Inserido com sucesso")

def insertData(idx,events):
    if not isinstance(events, list):
        events = [events]

    conn = getConn(idx)
    cursor = conn.cursor()

    values = [(event['_index'], event['_id'], event['_score'], json.dumps(event['_source'])) for event in events]
    cursor.executemany("INSERT INTO eventos (_index, _id, _score, _source) VALUES (?,?,?,?)", values)

    conn.commit()
    conn.close()
 
def retornaEventoPorId(id):
    try:
        return getData(f"SELECT _source FROM eventos WHERE _id = '{id}'").pop()[0]
    except Exception as e:
        # print(e)
        return False
    
def retornaIds():
    try:
        dbIds = getData("SELECT _id FROM eventos")  
        return [i[0] for i in dbIds]
    except Exception as e:
        print(e)
        return []
    
def retornaNumeroEventos(idx):    
    try:
        return getData(f"SELECT COUNT(*) FROM eventos WHERE _index = '{idx}'").pop()[0]
    except Exception as e:
        print(e)
        return []
 
def closeDb(cursor,conn):
    
    cursor.execute("VACUUM")
    conn.commit()
    conn.close()