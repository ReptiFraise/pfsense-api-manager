import requests
from requests.auth import HTTPBasicAuth
import json
import sys
import io


def read_rules(host,
               user,
               password):
    """
    Read the rules on router and show them on console
    :param host: ip address of router
    :param user: the username of user that have rights to use API
    :param password: the password of user
    :return: the rules in list of dicts format
    """
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
    """
    Get the parameters of a rule and returns it
    :param host: ip address of router
    :param user: the username of user that have rights to use API
    :param password: the password of user
    :param tracker: unique tracker id of a rule
    :return: parameters in dict format
    """
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
    """
    Add a rule on an interface of the router
    :param host: ip address of router
    :param user: the username of user that have rights to use API
    :param password: the password of user
    :param description: string description of the rule
    :param direction: direction of the rule, any by default
    :param dst: ip address of destination, can be "any" or network or alias
    :param dstport: port destination, can be range or alias
    :param interface: interface the rule will be applied on
    :param log: set True if you want to log the rule, False instead
    :param protocol: Set protocol over ip like TCP/UDP
    :param src: ip source, alias or network
    :param srcport: source port, any is the most used value
    :param type: pass, block or reject
    :param disabled: rule will be disabled if set as True, instead it will be False
    """
    url = f"https://{host}/api/v1/firewall/rule"
    data = json.dumps({"apply": True,
                       "descr": description,
                       "direction": "any",
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
                       "type": type})
    r = requests.post(url=url, 
                      verify=False, 
                      auth=HTTPBasicAuth(username=user, password=password),
                      data=data)
    print(r.status_code, r.text)


def modify_rule(host,
                user,
                password,
                description,
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
    """
    Modify a rule on an interface of the router, by default, the not modified parameters will be kept
    :param host: ip address of router
    :param user: the username of user that have rights to use API
    :param password: the password of user
    :param description: string description of the rule
    :param direction: direction of the rule, any by default
    :param dst: ip address of destination, can be "any" or network or alias
    :param dstport: port destination, can be range or alias
    :param interface: interface the rule will be applied on
    :param log: set True if you want to log the rule, False instead
    :param protocol: Set protocol over ip like TCP/UDP
    :param src: ip source, alias or network
    :param srcport: source port, any is the most used value
    :param type: pass, block or reject
    :param disabled: rule will be disabled if set as True, instead it will be False
    :param tracker: Unique tracker id of a rule
    """
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
                       "direction": "any",
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
