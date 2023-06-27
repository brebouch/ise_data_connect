import json
from data_connect import ISEDB

ise = ISEDB('config.yaml')
endpoints = ise.get_endpoints_data()
print(json.dumps(endpoints))
