import requests
from requests.auth import HTTPBasicAuth


def get_logs_system(host, user, password, logs):
    """
    Print the logs of the router, specify the category of logs
    :param host: the ip address of the router
    :param user: the username of user that have rights to use API
    :param password: the password of user
    :param logs: category of logs you want to show on console
    """
    url = f"https://{host}/api/v1/status/log/{logs}"
    r = requests.get(url=url, 
                     verify=False, 
                     auth=HTTPBasicAuth(username=user, password=password))
    datas = r.json()['data']
    for data in datas:
        print(data)