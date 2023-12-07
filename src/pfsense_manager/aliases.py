import requests
from requests.auth import HTTPBasicAuth
import json
import io
import sys




def get_aliases(host, user, password):
    url = f"https://{host}/api/v1/firewall/alias"
    print(f"Authentication with user {user}:{password}")
    r = requests.get(url=url, verify=False, auth=HTTPBasicAuth(username=user, password=password))
    datas = r.json()['data']
    for data in datas:
        print(f"{data['name']} :")
        for address in data['address'].split(" "):
            print(f"\t {address}")
    return datas

def add_address(host, user, password, alias, ip):
    url = f"https://{host}/api/v1/firewall/alias"
    original_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        datas = get_aliases(host=host, user=user, password=password)
    finally:
        sys.stdout = original_stdout
    aliases = []
    for data in datas:
        aliases.append(data['name'])
    if alias not in aliases:
        print("This alias does not exist, use pfsense-manager get-aliases [OPTIONS] to see the current aliases")
        pass
    else:
        liste = []
        for data in datas:
            if data['name'] == alias:
                liste = data['address'].split(" ")
        if ip.count(",") >= 1:
            for address in ip.split(","):
                if address not in liste:
                    liste.append(address)
                else:
                    print(f"Address {address} is already in alias")
        else:
            if ip not in liste:
                liste.append(ip)
            else:
                print(f"Address {address} is already in alias")
        addresses = json.dumps({"address": liste, "apply":True, "descr":"Allowed hosts on LAN", "id":alias, "name":alias, "type":"host"})
        r = requests.put(url=url, verify=False, auth=HTTPBasicAuth(username=user, password=password), data=addresses)
        print(r.status_code)
        if r.status_code == 200:
            print("IP addresses have been added")
        else:
            print("The programm got a problem while adding addresses")