import requests
from requests.auth import HTTPBasicAuth


def read_ca(host,
            username,
            password
            ):
    print("read the ca")
    url = f"https://{host}/api/v1/system/ca"
    r = requests.get(url=url,
                     verify=False,
                     auth=HTTPBasicAuth(username=username, password=password))
    datas = r.json()['data']
    for data in datas:
        print(f"Authority {data['descr']} has caref: {data['refid']}")
