from os import environ
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class Wazuh:
    def __init__(self):
        self.url_base = "https://172.29.252.6:9200"
        self.headers = {"Content-Type": "application/json"}
        self.auth = (
            environ.get('WAZUH_USER', 'jv.nunes'   ), 
            environ.get('WAZUH_PASS', 'k2C2g79(;S' )
        )

    def indices_request(self):
        url = self.url_base + '/_cat/indices?format=json'
        response = requests.get(url, headers=self.headers, auth=self.auth, verify=False)
        return response
    
    def data_request(self, idx, exclude_ids=None, size=10000):
        url = self.url_base + '/' + idx + '/_search?scroll=1m&format=json'
        if exclude_ids is None:
            query = {
                "size": int(size),
                "query": {
                    # 'exclude_ids': {
                    #      "values": ['gHTRiZMBFzPRs2NIUWhw']
                    #     }                     
                    "match_all": {}
                }
            }
        else:
            query = {
                "size": int(size),
                "query": {
                    "bool": {
                        "must_not": {
                            "ids": {
                                "values": exclude_ids
                            }
                        }
                    }
                },
                "sort": [
                    {"@timestamp": "asc"}  # Ou qualquer outro campo ordenável
                ]
            }
            
            
        response = requests.get(url, headers=self.headers, auth=self.auth, data=json.dumps(query), verify=False)
        return response
    
    def get_ids(self, resp):
        idsAr = []
        
        for event in resp:
            idsAr.append(event['_id'])
        
        return idsAr
