from   Wazuh import  Wazuh 
from   tqdm import tqdm
import logging

import banco_wazuh as bd

wzh = Wazuh()

def get_indices():
    indices = wzh.indices_request().json()
    wazuh_indices = [index['index'] for index in indices if 'wazuh-alerts' in index['index']]
    print(wazuh_indices)

def get_data(idx,ids=None,tam=10000):
    
    data = wzh.data_request(idx,exclude_ids=ids,size=tam)
    array = []
    
    try:
        for ev in data['hits']['hits']:
                
            evento = {
                '_index' : ev['_index'],
                '_id'    : ev['_id'],
                '_score' : ev['_score'],
                '_source': ev['_source']
            }
            
            array.append(evento)
                    
        return array
    
    except Exception as e:
        print(e)
        return []

def import_events_by_Id(idx,tam=10000):
    bd.createTables(idx)
    totalEventsCount = wzh.get_total_events(idx)
    idsExistentes = bd.retornaIds(idx) or []
    
    print(f'Total de Eventos do Index     = {totalEventsCount}')    
    print(f'Eventos já Inseridos no Banco = {(len(idsExistentes))}')
        
    pbar = tqdm(total=(totalEventsCount),initial=len(idsExistentes), desc='Buscando e Salvando Eventos', unit="events")
    
    while len(idsExistentes) < totalEventsCount:

        events = get_data(idx, ids=idsExistentes,tam=tam)
        
        bd.insertData(idx,events)
        
        idsExistentes.extend([event['_id'] for event in events])
        
        pbar.update(len(events))
    
    pbar.close()  
    
def import_events_by_timestamp(idx):
    bd.createTables(idx)
    total_events_count = wzh.get_total_events(idx)
    
    ids_existentes = bd.retornaIds() or []
    
    print(f"Total de Eventos do Index     = {total_events_count}")
    print(f"Eventos já Inseridos no Banco = {len(ids_existentes)}")
    
    pbar = tqdm(total=(total_events_count - len(ids_existentes)), initial=len(ids_existentes), desc="Importing events")
    
    while len(ids_existentes) < total_events_count:
        
        events = wzh.data_request2(idx, exclude_ids=ids_existentes, size=10000)
        
        if not events:
            break  
        
        bd.insertData(idx,events)
        
        ids_existentes.extend([event['_id'] for event in events])
        
        pbar.update(len(events))
    
    pbar.close()    

def fast_import_events(idx):
    print(f'Importando Eventos do Index = {idx}')
    bd.createTables(idx)
    
    totalEventsCount = wzh.get_total_events(idx)
    if int(totalEventsCount) > 2500000:
        print(f"Esse método suporta até 2,5 Mi Registros, o index inserido possui {totalEventsCount}\nSelecione outro método ")
        return []
    
    all_events = wzh.fetch_events_by_timestamp(idx)
    
    if len(all_events) != totalEventsCount:
        print(f'Diferenca na quantidade de eventos Eventos Importados = {len(all_events)}, Eventos no wazuh = {totalEventsCount} Difereça = {totalEventsCount - len(all_events)}')
        
    pbar = tqdm(total=len(all_events), initial=0, desc="Salvando Eventos no Banco", unit="events")
    
    batch_size = 10000
    for i in range(0, len(all_events), batch_size):
        try:
            batch_events = all_events[i:i+batch_size]
            bd.insertData(idx,batch_events)
            pbar.update(len(batch_events))
        except Exception as e:
            # print(f"Error inserting batch {i}: {e}")
            logging.error(f"Error inserting batch {i}: {e}")
    
    pbar.close()
    
def import_compressed_events(idx):
    totalEventsCount = wzh.get_total_events(idx)
    print(f'Total de Eventos do Index = {totalEventsCount}')
    
    all_events = wzh.fetch_events_by_timestamp(idx)
    
    pbear = tqdm(total=len(all_events), initial=0, desc="Comprimindo Eventos", unit="events")
    compressed_events = []
    for event in all_events:
        compressed_events.append(bd.compress_data(event))
        pbear.update(1)
    pbear.close()    
    
    pbar = tqdm(total=len(compressed_events), initial=0, desc="Salvando Eventos no Banco", unit="events")
    idx = bd.createTablesCompressed(idx)
    
    batch_size = 10000
    for i in range(0, len(compressed_events), batch_size):
        try:
            batch_events = compressed_events[i:i+batch_size]
            bd.insertDataCompressed(idx,batch_events)
            pbar.update(len(batch_events))
        except Exception as e:
            logging.error(f"Error inserting batch {i}: {e}")
    
    pbar.close()
    
def import_compressed_events_by_id(idx):
    total_events_count = wzh.get_total_events(idx)
    
    new_idx  = bd.createTablesCompressed(idx)
    ids_existentes = []
    
    print(f"Total de Eventos do Index = {total_events_count}")
    
    pbar = tqdm(total=(total_events_count), initial=len(ids_existentes), desc="Importing events")
    
    while len(ids_existentes) < total_events_count:
        try:               
            events = wzh.data_request2(idx, exclude_ids=ids_existentes, size=10000)
            
            if not events:
                break  
            
            compressed_events = []
            for event in events:
                compressed_events.append(bd.compress_data(event))
            
            bd.insertDataCompressed(new_idx,compressed_events)
            
            ids_existentes.extend([event['_id'] for event in events])
            
            pbar.update(len(ids_existentes))
        
        except Exception as e:
            print(f"Error inserting batch : {e}")
    
    pbar.close()    
    
# def return_events_from_db(idx):
#     return bd.getData(idx,"SELECT * FROM eventos") 

# def compress_existing_data_base(idx):
#     conn = bd.getConn(idx)
#     cursor = conn.cursor()
#     events = cursor.fetchall("SELECT * FROM eventos")
    
idx = 'wazuh-alerts-4.x-2024.12.16'
# import_compressed_events_by_id(idx)
# fast_import_events(idx)
import_events_by_Id(idx)
