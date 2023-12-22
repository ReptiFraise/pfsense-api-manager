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
def show_logs(host: Annotated[str, typer.Option(help="IP of pfsense")],
              logs: Annotated[str, typer.Option(help="system or firewall")],
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
def get_aliases(host: Annotated[str, typer.Option(help="IP of pfSense")],
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
                user: Annotated[str, typer.Option(help="usernanme")],
                password: Annotated[str, typer.Option(help="password")]):
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
def read_dhcp(host: Annotated[str, typer.Option(help="IP of pfSense")],
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
def add_rule(host: Annotated[str, typer.Option(help="IP of pfSense")],
             hosts: Annotated[str, typer.Option(help="File hosts.toml")],
             description: Annotated[str, typer.Option(help="Description of the rule")],
             direction: Annotated[str, typer.Option(help="Default any", default="any")],
             dst: Annotated[str, typer.Option(help="Destination of the rule [any, host or alias, Network, WAN net, WAN address, LAN net, LAN address]", default="any")],
             dstport: Annotated[str, typer.Option(help="Destination port of the rule [any, port number]")],
             interface: Annotated[str, typer.Option(help="Interface to apply the rule on [lan, wan]")],
             log: Annotated[bool, typer.Option(help="Default true", default=True)],
             protocol: Annotated[str, typer.Option(help="Protocol over IP [any, tcp, udp, tcp/udp, icmp ...]", default="tcp/udp")],
             src: Annotated[str, typer.Option(help="Source of traffic [any, host or alias, Network, WAN net, WAN address, LAN net, LAN address]", default="any")],
             srcport: Annotated[str, typer.Option(help="Source port of the rule [any, port number]", default="any")],
             disabled: Annotated[bool, typer.Option(help="Default False", default=False)],
             type: Annotated[str, typer.Option(help="[pass, block, reject]", default="pass")],
             user: Annotated[str, typer.Option(help="")],
             password: Annotated[str, typer.Option(help="")],
             passwords: Annotated[str, typer.Option(help="File of passwords .json.gpg")],
             gnupg: Annotated[str, typer.Option(help="Directory gnupg to decrypt .gpg file")]):
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
def modify_rule(host: Annotated[str, typer.Option(help="IP of pfSense", default=None)],
                hosts: Annotated[str, typer.Option(help="File hosts.toml", default=None)],
                description: Annotated[str, typer.Option(help="Description of the rule", default=None)],
                direction: Annotated[str, typer.Option(help="Default any", default="any", default=None)],
                dst: Annotated[str, typer.Option(help="Destination of the rule [any, host or alias, Network, WAN net, WAN address, LAN net, LAN address]", default=None)],
                dstport: Annotated[str, typer.Option(help="Destination port of the rule [any, port number]", default=None)],
                interface: Annotated[str, typer.Option(help="Interface to apply the rule on [lan, wan]", default=None)],
                log: Annotated[bool, typer.Option(help="Default true", default=None)],
                protocol: Annotated[str, typer.Option(help="Protocol over IP [any, tcp, udp, tcp/udp, icmp ...]", default=None)],
                src: Annotated[str, typer.Option(help="Source of traffic [any, host or alias, Network, WAN net, WAN address, LAN net, LAN address]", default=None)],
                srcport: Annotated[str, typer.Option(help="Source port of the rule [any, port number]", default=None)],
                disabled: Annotated[bool, typer.Option(help="Default False", default=None)],
                type: Annotated[str, typer.Option(help="[pass, block, reject]", default=None)],
                tracker: Annotated[str, typer.Option(help="tracker id of the rule to modify", default=None)],
                user: Annotated[str, typer.Option(help="", default=None)],
                password: Annotated[str, typer.Option(help="", default=None)],
                passwords: Annotated[str, typer.Option(help="File of passwords .json.gpg", default=None)],
                gnupg: Annotated[str, typer.Option(help="Directory gnupg to decrypt .gpg file", default=None)]
                ):
    """
    Modify Rule
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
