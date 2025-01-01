import mysql.connector
import logging
from datetime import datetime
from tqdm import tqdm

def getConn():
    return mysql.connector.connect(
        host      = "172.29.0.252",
        user      = "wazuh_events",
        database  = "wazuh_events",
        password  = "TInhoStOrOnE",
        charset   = "utf8mb4",  
        collation = "utf8mb4_general_ci",  
    )

def test_connection():
    try:
        conn = getConn()
        if conn.is_connected():
            print("Conexão bem-sucedida!")
        else:
            print("Falha na conexão.")
    except mysql.connector.Error as e:
        print(f"def test_connection: Erro ao conectar ao MySQL: {e}")
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()

def get_tables():
    table_names = []
    try:
        conn = getConn()
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        conn.close()

        for table in tables:
            table_names.append(table[0])

        return table_names

    except Exception as e:  
        print(f"def get_tables: Erro ao conectar ao MySQL: {e}")

def get_data(sql=None):
    try:
        conn = getConn()
        cursor = conn.cursor()
        cursor.execute(sql)
        data = cursor.fetchall()
        conn.close()
        return data

    except Exception as e:  
        print(f"def get_data: Erro ao conectar ao MySQL: {e}")

def get_columns(table_name=None):
    column_names = []
    try:
        conn = getConn()
        cursor = conn.cursor()
        cursor.execute(f"SHOW COLUMNS FROM {table_name}")
        columns = cursor.fetchall()
        conn.close()

        for column in columns:
            column_names.append(column[0])

        return column_names

    except Exception as e:  
        print(f"def get_columns: Erro ao conectar ao MySQL: {e}")

def insert_data(table_name=None,data=None,field_names=None):
    try:
        conn = getConn()
        cursor = conn.cursor()
        if field_names:
            query = f"INSERT INTO {table_name} ({', '.join(field_names)}) VALUES ({', '.join(['%s'] * len(field_names))})"
            cursor.execute(query, tuple(data.values()))
        else:
            print("Nenhum campo informado")

        conn.commit()
        conn.close()

        return cursor.lastrowid

    except Exception as e:  
        print(f'table Name {table_name} data {data}')
        print(f"def insert_data: Erro ao conectar ao MySQL: {e}")

def remove_data(table_name=None,data_key=None):
    try:
        conn = getConn()
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {table_name} WHERE chave = {data_key}")
        conn.commit()
        conn.close()

    except Exception as e:  
        print(f"def remove_data: Erro ao conectar ao MySQL: {e}")

def trucate_tables(table_name=None):
    if not table_name:
        print("Truncando todas as Tabelas")
        
        try:
            connection = getConn()
            cursor = connection.cursor()

            cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
        
            table_names = get_tables()
            for table in table_names:
                truncate_query = f"TRUNCATE TABLE `{table}`;"
                try:
                    cursor.execute(truncate_query)
                    print(f"Tabela {table} truncada.")
                except Exception as e:
                    print(f"Erro ao truncar a tabela {table}: {e}")

            cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
            connection.commit()

        except mysql.connector.Error as err:
            print(f"Erro ao acessar o banco de dados: {err}")

        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

def import_event(ar_events):
    pbar = tqdm(total=len(ar_events), desc="Importando Eventos", unit="events")
    
    for event in ar_events:
        try:
            if not event['_source']:
                break
            
            if event['_source'].get('agent'):  
                agent = event['_source'].get('agent')

                if agent.get('labels'):                
                    labels = {
                        'contrato' : agent['labels'].get('contrato', None),
                        '`group`'  : agent['labels'].get('group'   , None), # `group` é uma palavra reservada
                        '`group2`' : agent['labels'].get('group2'  , None), # `group` é uma palavra reservada
                        'vm'       : agent['labels'].get('vm'      , None)
                    }
                    
                    try:
                        agent_labels_key = insert_data(table_name='LABELS'.lower(),data=labels,field_names=labels.keys())
                        
                    except Exception as e:
                        print(f'Error inserting "labels" data: {e}')

                else:
                    agent_labels_key = None

                agente = {
                    'id'      : agent.get('id'   , None),
                    'ip'      : agent.get('ip'   , None),
                    'labels'  : agent_labels_key ,
                    'name'    : agent.get('name' , None)
                }
                agent_key = insert_data(table_name='AGENT'.lower(),data=agente, field_names=agente.keys())

            else:
                agent_key = None
                
            if event['_source'].get('data'):
                data = event['_source']['data']
                
                if data.get('os'):
                    os = {
                        'architecture' : data['os'].get('architecture', None),
                        'hostname'     : data['os'].get('hostname'    , None),
                        'name'         : data['os'].get('name'        , None),
                        'version'      : data['os'].get('version'     , None)
                    }
                    os_key = insert_data(table_name='OS'.lower(),data=os,field_names=os.keys())

                else:
                    os_key = None

                if data.get('port'):
                    port = {
                        'inode'      : data['port'].get('inode'         , None),
                        'local_ip'   : data['port'].get('local_ip'      , None),
                        'local_port' : data['port'].get('local_port'    , None),
                        'pid'        : data['port'].get('pid'           , None),
                        'process'    : data['port'].get('process'       , None),
                        'protocol'   : data['port'].get('protocol'      , None),
                        'remote_ip'  : data['port'].get('remote_ip'     , None),
                        'remote_port': data['port'].get('remote_port'   , None),
                        'rx_queue'   : data['port'].get('rx_queue'      , None),
                        'state'      : data['port'].get('state'         , None),
                        'tx_queue'   : data['port'].get('tx_queue'      , None)
                    }
                    port_key = insert_data(table_name='PORT'.lower(),data=port,field_names=port.keys())
                
                else:
                    port_key = None

                if data.get('process'):
                    process = {
                        'args'      : data['process'].get('args'       , None),
                        'cmd'       : data['process'].get('cmd'        , None),
                        'egroup'    : data['process'].get('egroup'     , None),
                        'euser'     : data['process'].get('euser'      , None),
                        'fgroup'    : data['process'].get('fgroup'     , None),
                        'name'      : data['process'].get('name'       , None),
                        'nice'      : data['process'].get('nice'       , None),
                        'nlwp'      : data['process'].get('nlwp'       , None),
                        'pgrp'      : data['process'].get('pgrp'       , None),
                        'pid'       : data['process'].get('pid'        , None),
                        'ppid'      : data['process'].get('ppid'       , None),
                        'priority'  : data['process'].get('priority'   , None),
                        'processor' : data['process'].get('processor'  , None),
                        'resident'  : data['process'].get('resident'   , None),
                        'rgroup'    : data['process'].get('rgroup'     , None),
                        'ruser'     : data['process'].get('ruser'      , None),
                        'session'   : data['process'].get('session'    , None),
                        'sgroup'    : data['process'].get('sgroup'     , None),
                        'share'     : data['process'].get('share'      , None),
                        'size'      : data['process'].get('size'       , None),
                        'start_time': data['process'].get('start_time' , None),
                        'state'     : data['process'].get('state'      , None),
                        'stime'     : data['process'].get('stime'      , None),
                        'suser'     : data['process'].get('suser'      , None),
                        'tgid'      : data['process'].get('tgid'       , None),
                        'tty'       : data['process'].get('tty'        , None),
                        'utime'     : data['process'].get('utime'      , None),
                        'vm_size'   : data['process'].get('vm_size'    , None),
                    }
                    process_key = insert_data(table_name='PROCESS'.lower(),data=process,field_names=process.keys())

                else:
                    process_key = None
                
                if data.get('vulnerability'):
                    if data['vulnerability'].get('cvss'):
                        cvss = data['vulnerability']['cvss']

                        if cvss.get('cvss2'):
                            cvss2 = cvss['cvss2']
                                                    
                            if cvss2.get('vector'): 
                                vector = {
                                    'access_complexity'      : cvss2['vector'].get('access_complexity'      , None),
                                    'attack_vector'          : cvss2['vector'].get('attack_vector'          , None),
                                    'authentication'         : cvss2['vector'].get('authentication'         , None),
                                    'availability'           : cvss2['vector'].get('availability'           , None),
                                    'confidentiality_impact' : cvss2['vector'].get('confidentiality_impact' , None),
                                    'integrity_impact'       : cvss2['vector'].get('integrity_impact'       , None),
                                    'privileges_required'    : cvss2['vector'].get('privileges_required'    , None),
                                    'scope'                  : cvss2['vector'].get('scope'                  , None),
                                    'user_interaction'       : cvss2['vector'].get('user_interaction'       , None)
                                }
                                vector_key = insert_data(table_name='VECTOR'.lower(),data=vector,field_names=vector.keys())
                                
                            else:
                                vector_key = None
                            
                            cvss2_obj = {   
                                'base_score'            : cvss2.get('base_score'           , None),
                                'exploitability_score'  : cvss2.get('exploitability_score' , None),
                                'impact_score'          : cvss2.get('impact_score'         , None),
                                'vector'                : vector_key
                            }
                            cvss2_key = insert_data(table_name='CVSS_CVSS'.lower(),data=cvss2_obj,field_names=cvss2_obj.keys())

                        else:
                            cvss2_key = None

                        if cvss.get('cvss3'):
                            cvss3 = cvss['cvss3']

                            if cvss3.get('vector'): 
                                vector = {
                                    'access_complexity'      : cvss3['vector'].get('access_complexity'      , None),
                                    'attack_vector'          : cvss3['vector'].get('attack_vector'          , None),
                                    'authentication'         : cvss3['vector'].get('authentication'         , None),
                                    'availability'           : cvss3['vector'].get('availability'           , None),
                                    'confidentiality_impact' : cvss3['vector'].get('confidentiality_impact' , None),
                                    'integrity_impact'       : cvss3['vector'].get('integrity_impact'       , None),
                                    'privileges_required'    : cvss3['vector'].get('privileges_required'    , None),
                                    'scope'                  : cvss3['vector'].get('scope'                  , None),
                                    'user_interaction'       : cvss3['vector'].get('user_interaction'       , None)
                                }
                                vector_key = insert_data(table_name='VECTOR'.lower(),data=vector,field_names=vector.keys())
                            else:
                                vector_key = None

                            cvss3_obj = {   
                                'base_score'            : cvss3.get('base_score'           , None),
                                'exploitability_score'  : cvss3.get('exploitability_score' , None),                                
                                'impact_score'          : cvss3.get('impact_score'         , None),
                                'vector'                : vector_key
                            }
                            cvss3_key = insert_data(table_name='CVSS_CVSS'.lower(),data=cvss3_obj,field_names=cvss3_obj.keys())

                        else:
                            cvss3_key = None

                        cvss = {
                            'cvss2' : cvss2_key,
                            'cvss3' : cvss3_key,
                        }
                        cvss_key = insert_data(table_name='CVSS'.lower(),data=cvss,field_names=cvss.keys())

                    else:
                        cvss_key = None

                    if data['vulnerability'].get('package'):
                        package = {
                            'architecture' : data['vulnerability']['package'].get('architecture' , None),
                            '`condition`'  : data['vulnerability']['package'].get('condition'    , None), # `condition` é uma palavra reservada
                            'name'         : data['vulnerability']['package'].get('name'         , None),
                            'source'       : data['vulnerability']['package'].get('source'       , None),
                            'version'      : data['vulnerability']['package'].get('version'      , None)
                        }
                        package_key = insert_data(table_name='PACKAGE'.lower(),data=package,field_names=package.keys())
                        
                    else:
                        package_key = None

                    if type(data['vulnerability'].get('advisories_ids' , None)) == list:
                        advisories_ids = ','.join(data['vulnerability'].get('advisories_ids'                , None))
                    else:
                        advisories_ids = data['vulnerability'].get('advisories_ids'                         , None)
                        
                    if type(data['vulnerability'].get('bugzilla_references' , None)) == list:
                        bugzilla_references = ','.join(data['vulnerability'].get('bugzilla_references'      , None))
                    else:
                        bugzilla_references = data['vulnerability'].get('bugzilla_references'               , None)
                        
                    if type(data['vulnerability'].get('references' , None)) == list:
                        references = ','.join(data['vulnerability'].get('references'                        , None))
                    else:
                        references = data['vulnerability'].get('references'                                 , None)
                        
                    vulnerability = {
                        'advisories_ids'      : advisories_ids,
                        'bugzilla_references' : bugzilla_references,
                        '`references`'        : references, # `references` é uma palavra reservada
                        'package'             : package_key,
                        'cvss'                : cvss_key,
                        'assigner'            : data['vulnerability'].get('assigner'                     , None),
                        'cve'                 : data['vulnerability'].get('cve'                          , None),
                        'published'           : data['vulnerability'].get('published'                    , None),
                        'rationale'           : data['vulnerability'].get('rationale'                    , None),
                        'severity'            : data['vulnerability'].get('severity'                     , None),
                        'status'              : data['vulnerability'].get('status'                       , None),
                        'title'               : data['vulnerability'].get('title'                        , None),
                        'type'                : data['vulnerability'].get('type'                         , None),
                        'updated'             : data['vulnerability'].get('updated'                      , None),
                        'cwe_reference'       : data['vulnerability'].get('cwe_reference'                , None),
                    }
                    vulnerability_key = insert_data(table_name='VULNERABILITY'.lower(),data=vulnerability,field_names=vulnerability.keys())

                else:
                    vulnerability_key = None

                if data.get('virustotal'):
                    virustotal = data['virustotal']

                    if virustotal.get('source'):
                        source = {
                            'alert_id' : virustotal['source'].get('alert_id' , None),
                            'file'     : virustotal['source'].get('file'     , None),
                            'md5'      : virustotal['source'].get('md5'      , None),
                            'sha1'     : virustotal['source'].get('sha1'     , None),
                        }
                        source_key = insert_data(table_name='SOURCE'.lower(),data=source,field_names=source.keys())
                        
                    else:
                        source_key = None

                    virustotal = {
                        'description' : virustotal.get('description' , None),
                        'error'       : virustotal.get('error'       , None),
                        'found'       : virustotal.get('found'       , None),
                        'malicious'   : virustotal.get('malicious'   , None),
                        'permalink'   : virustotal.get('permalink'   , None),
                        'positives'   : virustotal.get('positives'   , None),
                        'scan_date'   : virustotal.get('scan_date'   , None),
                        'sha1'        : virustotal.get('sha1'        , None),
                        'source'      : source_key,
                        'total'       : virustotal.get('total'       , None),
                    }
                    virustotal_key = insert_data(table_name='VIRUSTOTAL'.lower(),data=virustotal,field_names=virustotal.keys())

                else:
                    virustotal_key = None

                data_obj = {
                    'data'          : data.get('data'       ,None),
                    'dstport'       : data.get('dstport'    ,None),
                    'dstip'         : data.get('dstip'      ,None),
                    'dstuser'       : data.get('dstuser'    ,None),
                    'id'            : data.get('id'         ,None),
                    'os'            : os_key,
                    'port'          : port_key,
                    'process'       : process_key,
                    'protocol'      : data.get('protocol'   ,None),
                    'srcip'         : data.get('srcip'      ,None),
                    'srcport'       : data.get('srcport'    ,None),
                    'status'        : data.get('status'     ,None),
                    'title'         : data.get('title'      ,None),
                    'type'          : data.get('type'       ,None),
                    'uid'           : data.get('uid'        ,None),
                    'vulnerability' : vulnerability_key,
                    'virustotal'    : virustotal_key
                }  

                if all(value is None for value in data_obj.values()):
                    data_key = None

                else:               
                    data_key = insert_data(table_name='DATA'.lower(),data=data_obj,field_names=data_obj.keys())

            else:
                data_key = None
                

            timestamp  = event['_source'].get('timestamp' , None)
            date = datetime.strptime(timestamp[:-5], "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S")

            event_obj = {	
                'idx'       : event['_index'],
                'timestamp' : date,
                'agent'     : agent_key,
                'data'      : data_key,
                'id'        : event['_id'],
            }
                        
            insert_data(table_name='WAZUH_EVENTS'.lower(),data=event_obj,field_names=event_obj.keys())
            
            # print(f"Imported event with id: {event['_id']}")

            pbar.update(1)

        except Exception as e:
            print(f'Error importing event: {e}')

