from os import environ
import json
import requests
import urllib3
from tqdm import tqdm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Wazuh:
    def __init__(self):
        self.url_base = "https://172.29.252.6:9200"
        self.headers = {"Content-Type": "application/json"}
        self.auth = (
            environ.get('WAZUH_USER', 'jv.nunes'   ), 
            environ.get('WAZUH_PASS', 'Q1w2e3r4t5' )
        )
        
    def indices_request(self):
        url = self.url_base + '/_cat/indices?format=json'
        response = requests.get(url, headers=self.headers, auth=self.auth, verify=False)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            raise Exception(f"Error in response: {err}")
        return response
    
    def get_total_events(self,idx):
        url = self.url_base + '/' + idx + '/_count'
        query = {
            "query": {
                "match_all": {}  
            }
        }
        
        response = requests.post(url, headers=self.headers, auth=self.auth, json=query, verify=False)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            raise Exception(f"Erro na resposta: {err}")
        
        data = response.json()

        if "count" in data:
            return data["count"]  
        else:
            raise Exception(f"Erro na resposta: {data}")
        
    def data_request(self, idx, query=None, exclude_ids=None, size=10000):
        url = self.url_base + '/' + idx + '/_search?scroll=1m&format=json'
        if query is None:
            if exclude_ids is None:
                query = {
                    "size": int(size),
                    "query": {                 
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
                    }
                }
        try:
            response = requests.get(url, headers=self.headers, auth=self.auth, data=json.dumps(query), verify=False)
            return response.json()
        except Exception as e:
            print(e)
            return []

    def fetch_events_by_timestamp(self, idx, start_timestamp=None, batch_size=10000):
        url = self.url_base + '/' + idx + '/_search?format=json'
        headers = {"Content-Type": "application/json"}

        all_events = []
        last_sort_value = None 

        total_events = self.get_total_events(idx)
        pbar = tqdm(total=total_events, initial=0, desc="Buscando Eventos", unit="events")
        while True:
            query = {
                "size": batch_size,
                "sort": [
                    {"@timestamp": "asc"},
                    {"_id": "asc"} 
                ],
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": start_timestamp or "1970-01-01T00:00:00Z" 
                        }
                    }
                }
            }

            if last_sort_value:
                query["search_after"] = last_sort_value

            response = requests.post(url, headers=headers, auth=self.auth, json=query, verify=False)
            data = response.json()

            hits = data["hits"]["hits"]
            if not hits:
                break  

            all_events.extend(hits)

            last_sort_value = hits[-1]["sort"]

            pbar.update(len(hits))
        
        pbar.close()
        return all_events

    def data_request2(self, idx, query=None, exclude_ids=None, size=10000):
        url = self.url_base + '/' + idx + '/_search?scroll=1m&format=json'
        
        if query is None:
            if exclude_ids is None:
                query = {
                    "size": int(size),
                    "query": {
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
                    }
                }
        try:
            response = requests.get(url, headers=self.headers, auth=self.auth, data=json.dumps(query), verify=False)
            response_data = response.json()
            
            if "hits" in response_data and "hits" in response_data["hits"]:
                return response_data["hits"]["hits"]  
            else:
                return []  
        except Exception as e:
            print(f"Erro na resposta {e}")
            return []
        
        