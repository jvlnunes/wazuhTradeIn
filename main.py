from functions import  wazuh #, database
from os import environ
import json
wzh = wazuh.Wazuh()

def get_indices():
    indices = wzh.indices_request().json()
    wazuh_indices = [index['index'] for index in indices if 'wazuh-alerts' in index['index']]
    print(wazuh_indices)

def get_data(idx):
    data = wzh.data_request(idx).json()
    # print(data)
    for event in data['hits']['hits']:
        print('-----------------------------------')
        agent = event['_source']['agent']
        fulldata = event['_source'].get('data', 'null')
        if fulldata != 'null':
            os = event['_source']['data'].get('os', 'false')
        
            print(f"Agent_id: {agent['id']}")
            print(f"Agent_ip: {agent['ip']}")
            print(f"Agent_labels: {agent.get('labels', 'No labels available')}")
            print(f"Agent_name: {agent['name']}")
            print(f"DST_IP: {fulldata.get('dstip', 'null')}")
            print(f"DST_PORT: {fulldata.get('dstport', 'null')}")
            print(f"DST_USER: {fulldata.get('dstuser', 'null')}")
            print(f"ID: {fulldata.get('id', 'null')}")
            print(f"PORT: {fulldata.get('port', 'null')}")
            print(f"PROCESS: {fulldata.get('process', 'null')}")
            print(f"PROTOCOL: {fulldata.get('protocol', 'null')}")
            print(f"SRC_IP: {fulldata.get('srcip', 'null')}")
            print(f"SRC_PORT: {fulldata.get('srcport', 'null')}")
            print(f"STATUS: {fulldata.get('status', 'null')}")
            print(f"TITLE: {fulldata.get('title', 'null')}")
            print(f"TYPE: {fulldata.get('type', 'null')}")
            print(f"UID: {fulldata.get('uid', 'null')}")
            print(f"VULNERABILITY: {fulldata.get('vulnerability', 'null')}")
            print(f"VIRUS_TOTAL: {fulldata.get('virustotal', 'null')}")
            if os != 'false' :
                print(f"Os architecture: {os['architecture']}")
                print(f"Os hostname: {os['hostname']}")
                print(f"Os name: {os['name']}")
                print(f"Os version: {os['version']}")

get_data('wazuh-alerts-4.x-2024.12.03')