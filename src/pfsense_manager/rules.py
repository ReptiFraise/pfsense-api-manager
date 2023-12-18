import requests
from requests.auth import HTTPBasicAuth


def read_rules(host,
               user,
               password):
    url = f"https://{host}/api/v1/firewall/rule"
    r = requests.get(url=url, 
                     verify=False, 
                     auth=HTTPBasicAuth(username=user,
                                        password=password))
    datas = r.json()['data']
    lanrules = []
    wanrules = []
    for data in datas:
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

    print("")
