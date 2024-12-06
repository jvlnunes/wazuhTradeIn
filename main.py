from functions import  Wazuh #, database
from os import environ

import json
import banco as bd
from indices import Event

wzh = Wazuh()

def get_indices():
    indices = wzh.indices_request().json()
    wazuh_indices = [index['index'] for index in indices if 'wazuh-alerts' in index['index']]
    print(wazuh_indices)

def get_data(idx,ids=None,tam=10000):
    
    data = wzh.data_request(idx,ids,tam).json()
    array = []
    
    try:
        for ev in data['hits']['hits']:
                
            evento = Event(_index=ev['_index'], _id=ev['_id'], _score=ev['_score'], _source=ev['_source'])
            
            array.append(evento)
        
        return array
    
    except Exception as e:
        print(e)
        return []

def importEvents(idx,nEvents):
    idx = 'wazuh-alerts-4.x-2024.12.03'

    # data = wzh.get_data(idx)
    idsExistentes = bd.retornaIds()
    # print(f'idsExistentes = {idsExistentes}')
    eventsArray = get_data(idx,ids=idsExistentes)
    print(f'nEventos = {len(eventsArray)}')
    
    for ev in eventsArray:
        bd.insertData(ev)


idx = 'wazuh-alerts-4.x-2024.12.03'
# print(bd.retornaNumeroEventos(idx))
nEvents = 10

# data = get_data(idx,tam=nEvents)
importEvents(idx,nEvents)
# print(data[3]._source)