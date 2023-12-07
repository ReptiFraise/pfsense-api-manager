import requests
from requests.auth import HTTPBasicAuth
import json
import io
import sys

def get_logs_system(host, user, password):
    url = f"https://{host}/api/v1/status/log/system"
    r = requests.get(url=url, verify=False, auth=HTTPBasicAuth(username=user, password=password))
    datas = r.json()['data']
    for data in datas:
        print(data)