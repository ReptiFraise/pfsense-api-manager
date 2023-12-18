import requests
from requests.auth import HTTPBasicAuth


def read_dhcp(host,
              user,
              password):
    url = f"https://{host}/api/v1/services/dhcpd"
    r = requests.get(url=url, 
                     verify=False, 
                     auth=HTTPBasicAuth(username=user,
                                        password=password))
    datas = r.json()['data'][0]
    maps = datas['staticmap']
    print(datas)
    print("static mappings :")
    for number in range(len(maps)):
        print(f"\nmapping n°{number}:")
        for key in maps[number]:
            print(f"{key}:{maps[number][key]}")
