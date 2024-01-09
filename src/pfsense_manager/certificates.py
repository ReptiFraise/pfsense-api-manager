import requests
from requests.auth import HTTPBasicAuth
import json


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
                       type):
    print("Create a certificate")
    url = f"https://{host}/api/v1/system/certificate"
    dico = {
            "active": True,
            "altnames": [
                {}
            ],
            "caref": "659d5183d1e84",
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
    r = requests.post(url=url, verify=False, auth=HTTPBasicAuth(username=username, password=password), data=data)
    print(r.status_code, r.text)


def main(host,
         username,
         password,
         description,
         city,
         commonname,
         country,
         organization,
         organizationalunit,
         state,
         type):
    create_certificate(host,
                       username,
                       password,
                       description,
                       city,
                       commonname,
                       country,
                       organization,
                       organizationalunit,
                       state,
                       type)