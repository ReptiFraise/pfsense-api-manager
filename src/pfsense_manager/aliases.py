import requests
from requests.auth import HTTPBasicAuth
import json
import io
import sys
import ipaddress


def validate_ip_address(ip_string):
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        print("IP Address format isnt valid")
        return False


def get_aliases(host, user, password):
    url = f"https://{host}/api/v1/firewall/alias"
    print(f"Authentication with user {user}:{password}")
    r = requests.get(url=url, 
                     verify=False, 
                     auth=HTTPBasicAuth(username=user, password=password))
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
        print("""This alias does not exist, use pfsense-manager 
              get-aliases [OPTIONS] to see the current aliases""")
        pass
    else:
        liste = []
        for data in datas:
            if data['name'] == alias:
                liste = data['address'].split(" ")
        if ip.count(",") >= 1:
            for address in ip.split(","):
                if validate_ip_address(address):
                    if address not in liste:
                        liste.append(address)
                    else:
                        print(f"Address {address} is already in alias")
        
        elif '-' in ip:
            start_ip = ip.split("-")[0]
            end_ip = ip.split("-")[1]
            if validate_ip_address(start_ip) and validate_ip_address(end_ip):
                start = list(map(int, start_ip.split(".")))
                end = list(map(int, end_ip.split(".")))
                temp = start
                ip_range = []

                ip_range.append(start_ip)
                while temp != end:
                    start[3] += 1
                    for i in (3, 2, 1):
                        if temp[i] == 256:
                            temp[i] = 0
                            temp[i-1] += 1
                            print(f'ADDRESS == {".".join(map(str, temp))}')
                    ip_range.append(".".join(map(str, temp)))
                for add in ip_range:
                    if add in liste:
                        pass
                    else:
                        liste.append(add)
            else:
                exit()

        else:
            if validate_ip_address(ip):
                if ip not in liste:
                    liste.append(ip)
                else:
                    print(f"Address {address} is already in alias")
            else:
                exit()
        
        addresses = json.dumps({"address": liste, 
                                "apply": True, 
                                "descr": "Allowed hosts on LAN", 
                                "id": alias, 
                                "name": alias, 
                                "type": "host"})
        r = requests.put(url=url, 
                         verify=False, 
                         auth=HTTPBasicAuth(username=user, password=password), 
                         data=addresses)
        print(r.status_code)
        if r.status_code == 200:
            print("IP addresses have been added")
        else:
            print("The programm got a problem while adding addresses")