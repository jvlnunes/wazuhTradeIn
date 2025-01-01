        
def createTablesCompressed(idx):
    query = '''
            CREATE TABLE IF NOT EXISTS eventos (
                CHAVE INTEGER PRIMARY KEY AUTOINCREMENT,
                EVENT BLOB NOT NULL
            )    
    '''
    try:
        new_idx = "COMPRESSED_"+idx
        conn = getConn(new_idx)
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()
        
        conn.close()
        return new_idx
        
    except Exception as e:
        print(f'Error creating tables: {e}') #print(e)

def import_compressed_events(idx):
    totalEventsCount = wzh.get_total_events(idx)
    print(f'Total de Eventos do Index = {totalEventsCount}')
    
    all_events = wzh.fetch_events_by_timestamp(idx)
    
    pbear = tqdm(total=len(all_events), initial=0, desc="Comprimindo Eventos", unit="events")
    compressed_events = []
    for event in all_events:
        compressed_events.append(db.compress_data(event))
        pbear.update(1)
    pbear.close()    
    
    pbar = tqdm(total=len(compressed_events), initial=0, desc="Salvando Eventos no Banco", unit="events")
    idx = db.createTablesCompressed(idx)
    
    batch_size = 10000
    for i in range(0, len(compressed_events), batch_size):
        try:
            batch_events = compressed_events[i:i+batch_size]
            db.insertDataCompressed(idx,batch_events)
            pbar.update(len(batch_events))
        except Exception as e:
            logging.error(f"Error inserting batch {i}: {e}")
    
    pbar.close()
    
def import_compressed_events_by_id(idx):
    total_events_count = wzh.get_total_events(idx)
    
    new_idx  = db.createTablesCompressed(idx)
    ids_existentes = []
    
    print(f"Total de Eventos do Index = {total_events_count}")
    
    pbar = tqdm(total=(total_events_count), initial=len(ids_existentes), desc="Importando Eventos", unit="events")
    
    # while len(ids_existentes) < total_events_count:
    ids = 0
    for ids in range(total_events_count):
        try:               
            events = wzh.data_request2(idx, exclude_ids=ids_existentes, size=10000)
            
            if not events:
                break  
            
            compressed_events = []
            for event in events:
                compressed_events.append(db.compress_data(event))
            
            db.insertDataCompressed(new_idx,compressed_events)
            
            ids_existentes.extend([event['_id'] for event in events])
            logging.info(len(ids_existentes))
            
            pbar.update(10000)
            ids = len(ids_existentes)
        
        except Exception as e:
            print(f"Error inserting batch : {e}")
            break;
    
    pbar.close()    
    

         
def compress_data(data: dict) -> bytes:
    try:
        json_data = json.dumps(data)
        return zlib.compress(json_data.encode('utf-8'))
    except Exception as e:
        print(f'Error compressing data: {e}')

def decompress_data(data: bytes) -> dict:
    try:
        json_data = zlib.decompress(data).decode('utf-8') 
        return json.loads(json_data)
    except Exception as e:
        print(f'Error decompressing data: {e}')

def insertDataCompressed(idx,compressed_events):
    try:
        if not isinstance(compressed_events, list):
            compressed_events = [compressed_events]

        data_to_insert = [(event,) for event in compressed_events]

        conn = getConn(idx)
        cursor = conn.cursor()
        
        cursor.executemany("INSERT INTO eventos (EVENT) VALUES (?)", data_to_insert)
        
        conn.commit()
        conn.close()

    except Exception as e:
        print(f'Error inserting data: {e}')    