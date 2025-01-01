from import_functions import *
from functions_mysql  import *

from Wazuh import Wazuh 
wzh = Wazuh()

def main():
    # idx = get_indices().pop()
    idx = 'wazuh-alerts-4.x-2024.05.24'

    totalEventsCount = wzh.get_total_events(idx)
    print(f'{(totalEventsCount/1000000):.3f} Mi Eventos no Index "{idx}"')

    campos = ['agent','data','timestamp','@timestamp']
    
    # trucate_tables()
    # resp = wzh.data_request(idx,size=100)
    # print(get_data('ALTER TABLE vulnerability MODIFY `advisories_ids` TEXT;'))   
    # print(get_data('ALTER TABLE vulnerability MODIFY `references` TEXT;'))   
    resp = wzh.data_request_especified_columns(idx,columns=campos,size=10000)
    import_event(resp['hits']['hits'])
    # print(resp)	

    # resp = wzh.fetch_events_by_timestamp(idx)

    # print(resp['hits']['hits'])
    # print(type(resp['hits']['hits']))	
    # print(resp['hits']['hits'][0]['_source']['agent']['labels'])
    # remove_data(table_name='labels'.lower(),data_key=chave)

    # print(len(get_data('SELECT * FROM wazuh_events'))) 
    # print(get_data('SELECT Count(*) FROM wazuh_events group by id'))
    # print(get_data('SHOW COLUMNS FROM vulnerability'))   
    # print(wzh.return_events_with_specified_fields(idx,columns=['agent','data','data.virustotal'],size=1))
    
main()
