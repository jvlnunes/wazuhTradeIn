from os import environ
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Wazuh:
    def __init__(self):
        self.url_base = "https://172.29.252.6:9200"
        self.headers = {"Content-Type": "application/json"}
        # self.auth = ("jv.nunes@tradein.com.br", "123@Change")
        self.auth = (
            environ.get('WAZUH_USER', 'jv.nunes@tradein.com.br'),
            environ.get('WAZUH_PASS', '123@Change')
        )
    
    # def __init__(self):
    #     self.url_base = environ.get('WAZUH_URL', 'https://default-url:9200')
    #     self.headers = {"Content-Type": "application/json"}
    #     self.auth = (
    #         environ.get('WAZUH_USER', 'default_user'),
    #         environ.get('WAZUH_PASS', 'default_pass')
    #     )
        
    def indices_request(self):
        url = self.url_base + '/_cat/indices?format=json'
        response = requests.get(url, headers=self.headers, auth=self.auth, verify=False)
        return response
    
    def data_request(self, idx):
        url = self.url_base + '/' + idx + '/_search?format=json'
        query = {
            "size": 10000,
            "query": {
                # "bool": {
                #     "filter": [
                #         {"term": {"agent.id": 598}}
                #     ]
                # }
                "match_all": {}
            }
        }
        response = requests.get(url, headers=self.headers, auth=self.auth, data=json.dumps(query), verify=False)
        return response