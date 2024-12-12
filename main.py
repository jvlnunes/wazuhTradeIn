from functions import  Wazuh 
from tqdm import tqdm
import logging

import banco_wazuh as bd
#teste
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
    idsExistentes = bd.retornaIds() or []
    
    print(f'Total de Eventos do Index     = {totalEventsCount}')    
    print(f'Eventos já Inseridos no Banco = {(len(idsExistentes))}')
        
    pbar = tqdm(total=(totalEventsCount-len(idsExistentes)),initial=len(idsExistentes), desc='Importing events')
    
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
    
    
idx = 'wazuh-alerts-4.x-2024.10.26'
# import_events(idx)
# continue_import_events(idx)
# fast_import_events(idx)
# query = {
#     "query": {
#         "ids": {
#             "values": ["0oBFypIBDGHEftfh7IQl"]
#         }
#     }
# }
# print(wzh.data_request(idx,query)['hits']['hits'])

# totalEventsCount = wzh.get_total_events(idx)
# print(f'Total de Eventos do Index = {totalEventsCount}')
# idsExistentes = bd.retornaIds()
# print(f'Eventos já Inseridos = {(len(idsExistentes))}')
