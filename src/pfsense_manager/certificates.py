import requests
from requests.auth import HTTPBasicAuth
import json


def read_certs(host,
               username,
               password):
    print("read the certificates")
    print("read the ca")
    url = f"https://{host}/api/v1/system/certificate"
    r = requests.get(url=url,
                     verify=False,
                     auth=HTTPBasicAuth(username=username, password=password))
    datas = r.json()['data']
    for data in datas:
        print(f"Certificate: {data['descr']} has certfref: {data['refid']}")


def create_certificate(host,
                       username,
                       password,
                       description,
                       city,
                       commonname,
                       country,
                       organization,
                       organizationalunit,
                       state,
                       type,
                       caref):
    print("Create a certificate")
    url = f"https://{host}/api/v1/system/certificate"
    dico = {
            "active": True,
            "altnames": [
                {}
            ],
            "caref": caref,
            "descr": description,
            "digest_alg": "sha1",
            "dn_city": city,
            "dn_commonname": commonname,
            "dn_country": country,
            "dn_organization": organization,
            "dn_organizationalunit": organizationalunit,
            "dn_state": state,
            "ecname": "prime256v1",
            "keylen": 1024,
            "keytype": "RSA",
            "lifetime": 3650,
            "method": "internal",
            "type": type
            }
    data = json.dumps(dico)
    r = requests.post(url=url,
                      verify=False,
                      auth=HTTPBasicAuth(username=username, password=password),
                      data=data)
    print(r.status_code, r.text)
