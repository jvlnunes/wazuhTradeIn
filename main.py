from import_functions import *

def main():
    idx = get_indices()
    print(f'Iniciando Importacao de Eventos do Index = {idx}')
    import_compressed_events_by_id(idx[0])

main()