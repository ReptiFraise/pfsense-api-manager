import requests
from requests.auth import HTTPBasicAuth
import json


def add_port_forward():
    url = "https://192.168.3.254:8443/api/v1/firewall/nat/port_forward"
    dico = {
            "apply": True,
            "descr": "route",
            "disabled": False,
            "dst": "192.168.3.157",
            "dstbeginport_cust": "1",
            "dstendport_cust": "1",
            "interface": "lan",
            "localbeginport_cust": "1",
            "natreflection": "enable",
            "nordr": False,
            "nosync": False,
            "protocol": "tcp",
            "src": "any",
            "srcport": "any",
            "target": "10.200.1.78",
            "top": False
            }
    data = json.dumps(dico)
    r = requests.post(url=url, 
                      verify=False, 
                      auth=HTTPBasicAuth(username="admin", password="pfsense"),
                      data=data)
    print(r.status_code, r.text)


def main():
    add_port_forward()


if __name__ == "__main__":
    main()