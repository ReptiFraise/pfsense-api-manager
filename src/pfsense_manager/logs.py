import requests
from requests.auth import HTTPBasicAuth


def get_logs_system(host, user, password, logs):
    url = f"https://{host}/api/v1/status/log/{logs}"
    r = requests.get(url=url, 
                     verify=False, 
                     auth=HTTPBasicAuth(username=user, password=password))
    datas = r.json()['data']
    for data in datas:
        print(data)