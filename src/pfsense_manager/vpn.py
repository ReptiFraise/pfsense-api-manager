import requests
from requests.auth import HTTPBasicAuth
import json


def read_tls(file_path):
    """
    Read tls key file and returns content
    :param file_path: TLS key file path
    """
    ch = ""
    f = open(file_path, "r")
    lines = f.readlines()
    for line in lines:
        ch += line
    return ch


def create_vpn(host,
               username,
               password,
               caref,
               certref,
               tls_path,
               server_addr,
               server_port,
               description):
    """
    Create a new vpn client
    :param host: ip address of the router
    :param username: username to connect on api
    :param password: password of the user
    :param caref: CA ref id to sign vpn client
    :param certref: Certificate ref id to use with client
    :param tls_path: TLS key file path
    :param server_addr: vpn server ip addr
    :param server_port: vpn server port
    :param desciption: description of the vpn client
    """
    tls = read_tls(tls_path)
    url = f"https://{host}/api/v1/services/openvpn/client"
    dico = {
            "description": description,
            "mode": "p2p_tls",
            "dev_mode": "tun",
            "protocol": "UDP4",
            "interface": "wan",
            "server_addr": server_addr,
            "server_port": server_port,
            "proxy_authtype": "none",
            "auth-retry-none": "yes",
            "tlsauth_enable": "yes",
            "tls_type": "auth",
            "tls": tls,
            "tlsauth_keydir": "default",
            "caref": caref,
            "certref": certref,
            "data_ciphers[]": "AES-256-GCM",
            "data_ciphers[]": "AES-128-GCM",
            "data_ciphers_fallback": "AES-256-CBC",
            "digest": "SHA256",
            "engine": "none",
            "remote_cert_tls": "yes",
            "allow_compression": "no",
            "topology": "subnet",
            "inactive_seconds": 0,
            "ping_method": "keepalive",
            "keepalive_interval": 10,
            "keepalive_timeout": 60,
            "save": "Save",
            "act": "new"
            }

    data = json.dumps(dico)
    r = requests.post(url=url,
                      verify=False,
                      auth=HTTPBasicAuth(username=username, password=password),
                      data=data)
    print(r.status_code, r.text)
