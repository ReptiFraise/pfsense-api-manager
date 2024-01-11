import requests
from requests.auth import HTTPBasicAuth
import json


def add_package(host,
                user,
                password,
                package_name
                ):
    url = f"https://{host}/api/v1/firewall/rule"
    dico = {package_name}
    data = json.dumps(dico)
    r = requests.post(url=url, 
                      verify=False, 
                      auth=HTTPBasicAuth(username=user, password=password),
                      data=data)
    print(r.status_code, r.text)
