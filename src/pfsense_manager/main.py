import typer
from typing import Optional
from typing_extensions import Annotated
import toml
import os
import gnupg
from getpass import getpass
import json
import pfsense_manager.aliases as aliases
import pfsense_manager.logs as pflogs
import pfsense_manager.dhcp as dhcp
import pfsense_manager.rules as rules

app = typer.Typer()

ISTOML = False
if os.path.isfile("./config.toml"):
    TOML_DATA = toml.load("./config.toml")['user']
    ISTOML = True


def decrypt_gpg_file(file_path, gpg_home_path):
    gpg = gnupg.GPG(gnupghome=gpg_home_path)
    with open(file_path, 'rb') as f:
        passphrase = getpass(prompt="gpg key to decrypt .json.gpg file :")
        decrypted_data = gpg.decrypt_file(f,
                                          passphrase=passphrase,
                                          output=None,
                                          always_trust=True)
        print(decrypted_data)
    return decrypted_data.data.decode('utf-8')


def parse_json_data(json_string):
    return json.loads(json_string)


@app.command()
def show_logs(host: Annotated[str, typer.Argument(help="IP of pfsense")],
              logs: Annotated[str, typer.Argument(help="system or firewall")],
              user: Optional[str] = None,
              password: Optional[str] = None):
    """
    Read the vpn logs and create a file to be friendly readable
    """
    typer.echo(f"{logs}")
    if user is None and password is None and ISTOML:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        pflogs.get_logs_system(host=host,
                               user=user,
                               password=password,
                               logs=logs)
    else:
        pflogs.get_logs_system(host=host,
                               user=user,
                               password=password,
                               logs=logs)


@app.command()
def get_aliases(host,
                user: Optional[str] = None,
                password: Optional[str] = None):
    """
    Get aliases names
    """
    if user is None and password is None and ISTOML:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        aliases.get_aliases(host=host, user=user, password=password)
    else:
        aliases.get_aliases(host=host, user=user, password=password)


@app.command()
def add_address(host: Annotated[str, typer.Option(help="IP of pfSense")],
                alias: Annotated[str, typer.Option(help="Name of alias")],
                ip: Annotated[str, typer.Option(help="""ip @ format :
                                                  one @: x.x.x.x /
                                                  list: x.x.x.x,y.y.y.y /
                                                  range: x.x.x.x-y.y.y.y""")],
                user: Optional[str] = None, 
                password: Optional[str] = None):
    """
    Add an ip address or a list of ip addresses, separate addresses with comma.
    """
    if user is None and password is None and ISTOML:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        aliases.add_address(host=host,
                            user=user,
                            password=password,
                            alias=alias,
                            ip=ip)
    else:
        aliases.add_address(host=host,
                            user=user,
                            password=password,
                            alias=alias,
                            ip=ip)


@app.command()
def read_dhcp(host: Optional[str] = None,
              user: Optional[str] = None,
              password: Optional[str] = None):
    dhcp.read_dhcp(host=host,
                   user=user,
                   password=password)
    """Read dhcpd service parameters"""


@app.command()
def read_rules(host: Optional[str] = None,
               user: Optional[str] = None,
               password: Optional[str] = None):
    rules.read_rules(host=host,
                     user=user,
                     password=password)
    """Read dhcpd service parameters"""


@app.command()
def add_rule(host: Optional[str] = None,
             hosts: Optional[str] = None,
             description: Optional[str] = None,
             direction: Optional[str] = None,
             dst: Optional[str] = None,
             dstport: Optional[str] = None,
             interface: Optional[str] = None,
             log: Optional[bool] = None,
             protocol: Optional[str] = None,
             src: Optional[str] = None,
             srcport: Optional[str] = None,
             disabled: Optional[bool] = None,
             type: Optional[str] = "pass",
             user: Optional[str] = None,
             password: Optional[str] = None,
             passwords: Optional[str] = None,
             gnupg: Optional[str] = None
             ):
    """
    Add rule
    """
    if host is None and hosts is not None:
        hosts_data = toml.load(hosts)['routers']
        file_path = passwords
        gpg_home_path = gnupg
        decrypted_json_string = decrypt_gpg_file(file_path, gpg_home_path)
        decrypted_data_dict = parse_json_data(decrypted_json_string)
        print(f"decrypted_json_string = {decrypted_json_string}")
        for data in hosts_data:
            print(hosts_data[data])
            print(decrypted_data_dict[data])
            rules.add_rule(host=hosts_data[data],
                           user=user,
                           password=decrypted_data_dict[data],
                           description=description,
                           direction=direction,
                           dst=dst,
                           dstport=dstport,
                           interface=interface,
                           log=log,
                           protocol=protocol,
                           src=src,
                           type=type,
                           disabled=disabled,
                           srcport=srcport)
    else:
        if user is None and password is None and ISTOML:
            user = TOML_DATA['username']
            password = TOML_DATA['password']
            rules.add_rule(host=host,
                           user=user,
                           password=password,
                           description=description,
                           direction=direction,
                           dst=dst,
                           dstport=dstport,
                           interface=interface,
                           log=log,
                           protocol=protocol,
                           src=src,
                           type=type,
                           disabled=disabled,
                           srcport=srcport)
        else:
            rules.add_rule(host=host,
                           user=user,
                           password=password,
                           description=description,
                           direction=direction,
                           dst=dst,
                           dstport=dstport,
                           interface=interface,
                           log=log,
                           protocol=protocol,
                           src=src,
                           type=type,
                           disabled=disabled,
                           srcport=srcport)
            

@app.command()
def modify_rule(host: Optional[str] = None,
                hosts: Optional[str] = None,
                description: Optional[str] = None,
                direction: Optional[str] = "any",
                dst: Optional[str] = None,
                dstport: Optional[str] = None,
                interface: Optional[str] = None,
                log: Optional[bool] = True,
                protocol: Optional[str] = None,
                src: Optional[str] = None,
                srcport: Optional[str] = None,
                disabled: Optional[bool] = False,
                type: Optional[str] = "pass",
                tracker: Optional[str] = None,
                user: Optional[str] = None,
                password: Optional[str] = None,
                passwords: Optional[str] = None,
                gnupg: Optional[str] = None
                ):
    """
    Add rule
    """
    if host is None and hosts is not None:
        hosts_data = toml.load(hosts)['routers']
        file_path = passwords
        gpg_home_path = gnupg
        decrypted_json_string = decrypt_gpg_file(file_path, gpg_home_path)
        decrypted_data_dict = parse_json_data(decrypted_json_string)
        print(f"decrypted_json_string = {decrypted_json_string}")
        for data in hosts_data:
            print(hosts_data[data])
            print(decrypted_data_dict[data])
            rules.modify_rule(host=hosts_data[data],
                              user=user,
                              password=decrypted_data_dict[data],
                              description=description,
                              direction=direction,
                              dst=dst,
                              dstport=dstport,
                              interface=interface,
                              log=log,
                              protocol=protocol,
                              src=src,
                              type=type,
                              tracker=tracker,
                              disabled=disabled,
                              srcport=srcport)
    else:
        if user is None and password is None and ISTOML:
            user = TOML_DATA['username']
            password = TOML_DATA['password']
            rules.modify_rule(host=host,
                              user=user,
                              password=password,
                              description=description,
                              direction=direction,
                              dst=dst,
                              dstport=dstport,
                              interface=interface,
                              log=log,
                              protocol=protocol,
                              src=src,
                              type=type,
                              tracker=tracker,
                              disabled=disabled,
                              srcport=srcport)
        else:
            rules.modify_rule(host=host,
                              user=user,
                              password=password,
                              description=description,
                              direction=direction,
                              dst=dst,
                              dstport=dstport,
                              interface=interface,
                              log=log,
                              protocol=protocol,
                              src=src,
                              type=type,
                              tracker=tracker,
                              disabled=disabled,
                              srcport=srcport)
