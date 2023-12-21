import requests
from requests.auth import HTTPBasicAuth
import json


def read_rules(host,
               user,
               password):
    url = f"https://{host}/api/v1/firewall/rule"
    r = requests.get(url=url, 
                     verify=False, 
                     auth=HTTPBasicAuth(username=user,
                                        password=password))
    datas = r.json()['data']
    print(datas)
    lanrules = []
    wanrules = []
    for data in datas:
        print(data)
        if data['interface'] == 'wan':
            wanrules.append(data)
        if data['interface'] == 'lan':
            lanrules.append(data)
    print("LAN RULES:")
    for number in range(len(lanrules)):
        if number != 0:
            print("\n")
        for key in lanrules[number]:
            print(f"\t{key}:{lanrules[number][key]}")
    print("\n")
    print("WAN RULES:")
    for number in range(len(wanrules)):
        if number != 0:
            print("\n")
        for key in wanrules[number]:
            print(f"\t{key}:{wanrules[number][key]}")


def add_rules(host,
              user,
              password,
              description,
              direction,
              dst,
              dstport,
              interface,
              log,
              protocol,
              src,
              srcport,
              ):
    url = f"https://{host}/api/v1/firewall/rule"
    data = json.dumps({"apply": True,
                       "descr": description,
                       "direction": direction,
                       "disabled": False,
                       "dst": dst,
                       "dstport": dstport,
                       "interface": [
                           interface
                       ],
                       "ipprotocol": "inet",
                       "log": log,
                       "protocol": protocol,
                       "src": src,
                       "srcport": srcport,
                       "top": True,
                       "type": "pass"})
    r = requests.post(url=url, 
                      verify=False, 
                      auth=HTTPBasicAuth(username=user, password=password),
                      data=data)
    print(r.status_code, r.text)
