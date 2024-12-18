from import_functions import *
# def return_events_from_db(idx):
#     return db.getData(idx,"SELECT * FROM eventos") 

# def compress_existing_data_base(idx):
#     conn = db.getConn(idx)
#     cursor = conn.cursor()
#     events = cursor.fetchall("SELECT * FROM eventos")
    

# idx = 'wazuh-alerts-4.x-2024.12.16'
# import_compressed_events_by_id(idx)
# fast_import_events(idx)
# import_events_by_Id(idx)


def main():
    idx = get_indices()
    print(f'Iniciando Importacao de Eventos do Index = {idx}')
    import_compressed_events_by_id(idx[0])

main()