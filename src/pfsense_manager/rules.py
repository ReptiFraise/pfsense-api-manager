import requests
from requests.auth import HTTPBasicAuth
import json
import sys
import io


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
    return datas


def get_rule_parameters(host,
                        user,
                        password,
                        tracker):
    original_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        datas = read_rules(host=host,
                           user=user,
                           password=password)
    finally:
        sys.stdout = original_stdout
    for data in datas:
        if data['tracker'] == tracker:
            return data
    

def add_rule(host,
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
             type,
             disabled
             ):
    url = f"https://{host}/api/v1/firewall/rule"
    data = json.dumps({"apply": True,
                       "descr": description,
                       "direction": direction,
                       "disabled": disabled,
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


def modify_rule(host,
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
                disabled,
                type,
                tracker):
    url = f"https://{host}/api/v1/firewall/rule"
    parameters = get_rule_parameters(host=host,
                                     user=user,
                                     password=password,
                                     tracker=tracker)
    print(f"parameters = {parameters}")
    if description is None:
        description = parameters['descr']
        print(description)
    if dst is None:
        try:
            cle = list(parameters['destination'])[0]
            val = parameters['destination'][cle]
            dst = val
        except ValueError:
            exit()
    if dstport is None:
        try:
            cle = list(parameters['destination'])[1]
            val = parameters['destination'][cle]
            dstport = val
        except ValueError:
            exit()
    if interface is None:
        interface = parameters['interface']
    if protocol is None:
        protocol = parameters['protocol']
    if src is None:
        try:
            cle = list(parameters['source'])[0]
            val = parameters['source'][cle]
            src = val
        except ValueError:
            exit()
    if srcport is None:
        try:
            cle = list(parameters['source'])[1]
            val = parameters['source'][cle]
            srcport = val
        except ValueError:
            exit()
    data = json.dumps({"apply": True,
                       "descr": description,
                       "direction": direction,
                       "disabled": disabled,
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
                       "type": type,
                       "tracker": tracker})
    r = requests.put(url=url, 
                     verify=False, 
                     auth=HTTPBasicAuth(username=user, password=password),
                     data=data)
    print(r.status_code, r.text)
