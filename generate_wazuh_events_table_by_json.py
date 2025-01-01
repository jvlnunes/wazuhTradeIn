import json

def get_columns(properties, parent_key=""):

    columns = []
    for key, value in properties.items():
        field_name = f"{parent_key}_{key}" if parent_key else key

        if "properties" in value:
            nested_columns = get_columns(value["properties"], field_name.lower())
            columns.extend(nested_columns)

        else:
            type_value = value.get("type", "text")
            if type_value == "keyword":
                sql_type = "VARCHAR(255)"

            elif type_value == "text":
                sql_type = "TEXT"

            elif type_value == "long" or type_value == "integer":
                sql_type = "INT"

            elif type_value == "float" or type_value == "double":
                sql_type = "FLOAT"

            elif type_value == "date":
                sql_type = "DATETIME"

            elif type_value == "boolean":
                sql_type = "BOOLEAN"

            else:
                sql_type = "TEXT"

            columns.append(f"{field_name.lower()} {sql_type}")

    return columns

def get_sql_table_from_json(mappings, table_name):
  
    properties = mappings['mappings']['properties']
    columns = get_columns(properties)

    sql = (
        "CREATE TABLE {} (\n    key INT AUTO_INCREMENT PRIMARY KEY,\n    index TEXT NOT NULL, \n    id TEXT NOT NULL UNIQUE,\n    {}\n);".format(table_name, ",\n    ".join(columns))
    )
    return sql

def get_sql_table_from_object(campo_requeridos, nome_tabela):
   
    colunas = []
    for campo_pai, campos_filhos in campo_requeridos.items():
        for campo_filho in campos_filhos:
            coluna = f"{campo_pai}_{campo_filho} VARCHAR(255)"
            colunas.append(coluna)

    colunas_str = ",\n    ".join(colunas)
    query = f"""
    CREATE TABLE {nome_tabela} (
        id INT AUTO_INCREMENT PRIMARY KEY,
        {colunas_str}
    );
    """
    return query
    try:
        cursor.execute(query)
        conexao.commit()
        print(f"Tabela {nome_tabela} criada com sucesso!")
    except mysql.connector.Error as err:
        print(f"Erro ao criar a tabela: {err}")
    finally:
        cursor.close()


campos_requeridos = {
    # Campo pai             : [campos filhos]
    'agent'                 : ['id'      , 'ip'    ,  'labels' , 'name'],
    'agent_labels'          : ['contrato', 'group' ,  'group2' , 'vm'  ],
    
    'data'                  : ['dstip'          , 'dstport'  , 'id'    , 'os', 'data', 'dstuser', 'port', 'process', 'protocol', 'srcip', 'srcport', 'status', 'title', 'type', 'uid', 'vulnerability','virustotal'],
    'data_process'          : ["args"           , "cmd"      , "egroup","euser","fgroup","name","nice","nlwp","pgrp","pid","ppid","priority","processor","resident","rgroup","ruser","session","sgroup","share","size","start_time","state","stime","suser","tgid","tty","utime","vm_size"],
    'data_os'               : ['architecture'   , 'hostname' , 'name', 'version'],
    'data_port'             : ['inode','local_ip','local_port', 'pid', 'process', 'protocol', 'remote_ip', 'remote_port', 'rx_queue', 'state', 'tx_queue'],
    'data_vulnerability'    : ['advisories_ids' , 'assigner' , 'bugzilla_references','cve','cvss','package','published','rationale','references','severity','status','title','type','updated'],
    'data_virustotal'       : ['description'    , 'error'    , 'found','malicious','permalink','positives','scan_date','sha1','source','total'],

    'vulnerability_cvss'    : ['cvss2'        , 'cvss3'     , 'cwe_reference'],
    'vulnerability_package' : ['architecture' , 'condition' , 'name'         , 'source' , 'version' ],

    'cvss_cvss2'            : ["base_score"        , "exploitability_score" ,  "impact_score"   , "vector" ],
    'cvss_cvss3'            : ["base_score"        , "exploitability_score" ,  "impact_score"   , "vector" ],
    'cvss2_vector'          : ['access_complexity' , 'attack_vector'        ,  'authentication' , 'availability', 'confidentiality_impact', 'integrity_impact', 'privileges_required', 'scope', 'user_interaction'],
    'cvss3_vector'          : ['access_complexity' , 'attack_vector'        ,  'authentication' , 'availability', 'confidentiality_impact', 'integrity_impact', 'privileges_required', 'scope', 'user_interaction'],
    
    'virustotal_source'     : ['alert_id', 'file', 'md5','sha1'],
}

mapping_campos = {
    "mappings": {
        "properties": {
            "id":{
                "type": "keyword"
            },            
            "index":{
                "type": "keyword"
            },
            "@timestamp": {
                "type": "date"
            },
            "agent": {
                "properties": {
                    "id": {
                        "type": "keyword"
                    },
                    "ip": {
                        "type": "keyword"
                    },
                    "labels": {
                        "properties": {
                            "contrato": {
                                "type": "keyword"
                            },
                            "group": {
                                "type": "keyword"
                            },
                            "group2": {
                                "type": "keyword"
                            },
                            "vm": {
                                "type": "keyword"
                            }
                        }
                    },
                    "name": {
                        "type": "keyword"
                    }
                }
            },
            "data": {
                "properties": {      
                    "data": {
                        "type": "keyword"
                    },
                    "dstip": {
                        "type": "keyword"
                    },
                    "dstport": {
                        "type": "keyword"
                    },
                    "dstuser": {
                        "type": "keyword"
                    },            
                    "id": {
                        "type": "keyword"
                    },
                    "os": {
                        "properties": {
                            "architecture": {
                                "type": "keyword"
                            },
                            "build": {
                                "type": "keyword"
                            },
                            "codename": {
                                "type": "keyword"
                            },
                            "display_version": {
                                "type": "keyword"
                            },
                            "hostname": {
                                "type": "keyword"
                            },
                            "major": {
                                "type": "keyword"
                            },
                            "minor": {
                                "type": "keyword"
                            },
                            "name": {
                                "type": "keyword"
                            },
                            "patch": {
                                "type": "keyword"
                            },
                            "platform": {
                                "type": "keyword"
                            },
                            "release": {
                                "type": "keyword"
                            },
                            "release_version": {
                                "type": "keyword"
                            },
                            "sysname": {
                                "type": "keyword"
                            },
                            "version": {
                                "type": "keyword"
                            }
                        }
                    },            
                    "port": {
                        "properties": {
                            "inode": {
                                "type": "long"
                            },
                            "local_ip": {
                                "type": "ip"
                            },
                            "local_port": {
                                "type": "long"
                            },
                            "pid": {
                                "type": "long"
                            },
                            "process": {
                                "type": "keyword"
                            },
                            "protocol": {
                                "type": "keyword"
                            },
                            "remote_ip": {
                                "type": "ip"
                            },
                            "remote_port": {
                                "type": "long"
                            },
                            "rx_queue": {
                                "type": "long"
                            },
                            "state": {
                                "type": "keyword"
                            },
                            "tx_queue": {
                                "type": "long"
                            }
                        }
                    },
                    "process": {
                        "properties": {
                            "args": {
                                "type": "keyword"
                            },
                            "cmd": {
                                "type": "keyword"
                            },
                            "egroup": {
                                "type": "keyword"
                            },
                            "euser": {
                                "type": "keyword"
                            },
                            "fgroup": {
                                "type": "keyword"
                            },
                            "name": {
                                "type": "keyword"
                            },
                            "nice": {
                                "type": "long"
                            },
                            "nlwp": {
                                "type": "long"
                            },
                            "pgrp": {
                                "type": "long"
                            },
                            "pid": {
                                "type": "long"
                            },
                            "ppid": {
                                "type": "long"
                            },
                            "priority": {
                                "type": "long"
                            },
                            "processor": {
                                "type": "long"
                            },
                            "resident": {
                                "type": "long"
                            },
                            "rgroup": {
                                "type": "keyword"
                            },
                            "ruser": {
                                "type": "keyword"
                            },
                            "session": {
                                "type": "long"
                            },
                            "sgroup": {
                                "type": "keyword"
                            },
                            "share": {
                                "type": "long"
                            },
                            "size": {
                                "type": "long"
                            },
                            "start_time": {
                                "type": "long"
                            },
                            "state": {
                                "type": "keyword"
                            },
                            "stime": {
                                "type": "long"
                            },
                            "suser": {
                                "type": "keyword"
                            },
                            "tgid": {
                                "type": "long"
                            },
                            "tty": {
                                "type": "long"
                            },
                            "utime": {
                                "type": "long"
                            },
                            "vm_size": {
                                "type": "long"
                            }
                        }
                    },           
                    "protocol": {
                        "type": "keyword"
                    },
                    "srcip": {
                        "type": "keyword"
                    },
                    "srcport": {
                        "type": "keyword"
                    },
                    "status": {
                        "type": "keyword"
                    },
                    "title": {
                        "type": "keyword"
                    },
                    "type": {
                        "type": "keyword"
                    },  
                    "uid": {
                        "type": "keyword"
                    },
                    "virustotal": {
                        "properties": {
                            "description": {
                                "type": "keyword"
                            },
                            "error": {
                                "type": "keyword"
                            },
                            "found": {
                                "type": "keyword"
                            },
                            "malicious": {
                                "type": "keyword"
                            },
                            "permalink": {
                                "type": "keyword"
                            },
                            "positives": {
                                "type": "keyword"
                            },
                            "scan_date": {
                                "type": "keyword"
                            },
                            "sha1": {
                                "type": "keyword"
                            },
                            "source": {
                                "properties": {
                                    "alert_id": {
                                        "type": "keyword"
                                    },
                                    "file": {
                                        "type": "keyword"
                                    },
                                    "md5": {
                                        "type": "keyword"
                                    },
                                    "sha1": {
                                        "type": "keyword"
                                    }
                                }
                            },
                            "total": {
                                "type": "keyword"
                            }
                        }
                    },
                    "vulnerability": {
                        "properties": {
                            "assigner": {
                                "type": "keyword"
                            },
                            "bugzilla_references": {
                                "type": "keyword"
                            },
                            "cve": {
                                "type": "keyword"
                            },
                            "cve_version": {
                                "type": "keyword"
                            },
                            "cvss": {
                                "properties": {
                                    "cvss2": {
                                        "properties": {
                                            "base_score": {
                                                "type": "keyword"
                                            },
                                            "exploitability_score": {
                                                "type": "keyword"
                                            },
                                            "impact_score": {
                                                "type": "keyword"
                                            },
                                            "vector": {
                                                "properties": {
                                                    "access_complexity": {
                                                        "type": "keyword"
                                                    },
                                                    "attack_vector": {
                                                        "type": "keyword"
                                                    },
                                                    "authentication": {
                                                        "type": "keyword"
                                                    },
                                                    "availability": {
                                                        "type": "keyword"
                                                    },
                                                    "confidentiality_impact": {
                                                        "type": "keyword"
                                                    },
                                                    "integrity_impact": {
                                                        "type": "keyword"
                                                    },
                                                    "privileges_required": {
                                                        "type": "keyword"
                                                    },
                                                    "scope": {
                                                        "type": "keyword"
                                                    },
                                                    "user_interaction": {
                                                        "type": "keyword"
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    "cvss3": {
                                        "properties": {
                                            "base_score": {
                                                "type": "keyword"
                                            },
                                            "exploitability_score": {
                                                "type": "keyword"
                                            },
                                            "impact_score": {
                                                "type": "keyword"
                                            },
                                            "vector": {
                                                "properties": {
                                                    "access_complexity": {
                                                        "type": "keyword"
                                                    },
                                                    "attack_vector": {
                                                        "type": "keyword"
                                                    },
                                                    "authentication": {
                                                        "type": "keyword"
                                                    },
                                                    "availability": {
                                                        "type": "keyword"
                                                    },
                                                    "confidentiality_impact": {
                                                        "type": "keyword"
                                                    },
                                                    "integrity_impact": {
                                                        "type": "keyword"
                                                    },
                                                    "privileges_required": {
                                                        "type": "keyword"
                                                    },
                                                    "scope": {
                                                        "type": "keyword"
                                                    },
                                                    "user_interaction": {
                                                        "type": "keyword"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "cwe_reference": {
                                "type": "keyword"
                            },
                            "package": {
                                "properties": {
                                    "architecture": {
                                        "type": "keyword"
                                    },
                                    "condition": {
                                        "type": "keyword"
                                    },
                                    "generated_cpe": {
                                        "type": "keyword"
                                    },
                                    "name": {
                                        "type": "keyword"
                                    },
                                    "source": {
                                        "type": "keyword"
                                    },
                                    "version": {
                                        "type": "keyword"
                                    }
                                }
                            },
                            "published": {
                                "type": "date"
                            },
                            "rationale": {
                                "type": "keyword"
                            },
                            "references": {
                                "type": "keyword"
                            },
                            "severity": {
                                "type": "keyword"
                            },
                            "status": {
                                "type": "keyword"
                            },
                            "title": {
                                "type": "keyword"
                            },
                            "type": {
                                "type": "keyword"
                            },
                            "updated": {
                                "type": "date"
                            }
                        }
                    }, 
                }
            },
        }
    }
}

with open("Wazuh_Events_Mapping.json", "r") as file:
    mapping = json.load(file)

table_name = "wazuh_events"
sql_script = get_sql_table_from_json(mapping_campos, table_name)
print(sql_script)
