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
import pfsense_manager.fields as fields

app = typer.Typer()

ISTOML = False
if os.path.isfile("./config.toml"):
    TOML_DATA = toml.load("./config.toml")['user']
    ISTOML = True


def decrypt_gpg_file(file_path, gpg_home_path):
    """
    Decrypt a .gpg file
    :param file_path: File path of encrypted .gpg file
    :param gpg_home_path: Path of folder gnupg
    :return: File content decrypted
    """
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
    """
    Return the content of .gpg file to json format
    :param json_strin: The content of .gpg file decrypted
    :return: A dict in json format
    """
    return json.loads(json_string)


@app.command()
def show_logs(host: Annotated[str, typer.Option(help="IP of pfsense")],
              logs: Annotated[str, typer.Option(help="system or firewall")],
              user: Optional[str] = None,
              password: Optional[str] = None):
    """
    Read the logs and print them on console
    :param host: The IP address of the pfsense
    :param logs: The type of logs [System,firewall]
    :param user: The username to connect with
    :param password: The password of the user
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
    :param host: The IP address of the pfsense
    :param user: The username to connect with
    :param password: The password of the user
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
    Add an ip address, a list or a range of addresses
    :param host: The IP address of the pfsense
    :param alias: Name of the alias to add an address inside
    :param ip: The ip address, list or range to add
    :param user: The username to connect with
    :param password: The password of the user
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
    """
    Read dhcpd service parameters
    :param host: The IP address of the pfsense
    :param user: The username to connect with
    :param password: The password of the user
    """
    dhcp.read_dhcp(host=host,
                   user=user,
                   password=password)
    

@app.command()
def read_rules(host: Optional[str] = None,
               user: Optional[str] = None,
               password: Optional[str] = None):
    """
    Read rules of the firewall
    :param host: The IP address of the pfsense
    :param user: The username to connect with
    :param password: The password of the user
    """
    rules.read_rules(host=host,
                     user=user,
                     password=password)


@app.command()
def add_rule(host: Optional[str] = None,
             hosts: Optional[str] = None,
             user: Optional[str] = None,
             password: Optional[str] = None,
             passwords: Optional[str] = None,
             gnupg: Optional[str] = None,
             description: Optional[str] = None,
             dst: Optional[str] = "any",
             dstport: Optional[str] = "any",
             interface: Optional[str] = None,
             log: Optional[bool] = True,
             protocol: Optional[str] = "any",
             src: Optional[str] = "any",
             srcport: Optional[str] = "any",
             disabled: Optional[bool] = False,
             type: Optional[str] = "pass"):
    """
    Add rule on the pfSense
    :param host: The IP address of the pfsense
    :param hosts: The hosts.toml file that contain hostnames and ip addresses
    :param user: The username to connect with
    :param password: The password of the user
    :param passwords: The password of the user
    :param gnupg: Path of folder gnupg
    :param description: The description of the rule
    :param dst: The destination of the rule [any, ip address, network, alias]
    :param dstport: The port destination [any, port number]
    :param interface: The interface to apply the rule on
    :param log: Bool to log or not the traffic rules
    :param protocol: IP protocol [any, tcp, udp, tcp/udp, icmp]
    :param src: Source of the traffic [any, ip address, network, alias]
    :param srcport: Port source [any, port number]
    :param disabled: Bool to disable or not the rule
    :param type: Type of the rul [pass, block, reject]
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
    Modify a rule by tracker id
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


@app.command()
def transfert_field(host: Optional[str] = None,
                    hosts: Optional[str] = None,
                    name: Optional[str] = None,
                    port: Optional[str] = None,
                    username: Optional[str] = None,
                    password: Optional[str] = None,
                    passwords: Optional[str] = None,
                    field: Optional[str] = None,
                    template: Optional[str] = None,
                    gnupg: Optional[str] = None,
                    ):
    """
   Transfert a field from a config.xml file template to another one
   :param host: Router ip address
   :param name: name of the router that will be used to create file 'name'.xml
   :param port: ssh port of router
   :param username: username to connect on ssh, user need rights to copy /conf/config.xml
   :param password: user's password
   :param field: field you want to replace on new file
   :param template: path of the config.xml template file from which you want to get field datas
    """
    if host is None and hosts is not None:
        hosts_data = toml.load(hosts)['routers']
        file_path = passwords
        gpg_home_path = gnupg
        decrypted_json_string = decrypt_gpg_file(file_path, gpg_home_path)
        decrypted_data_dict = parse_json_data(decrypted_json_string)
        print(f"decrypted_json_string = {decrypted_json_string}")
        for data in hosts_data:
            fields.main(host=hosts_data[data],
                        username=username,
                        password=decrypted_data_dict[data],
                        name=name,
                        port=port,
                        field=field,
                        template=template)
    else:
        if username is None and password is None and ISTOML:
            username = TOML_DATA['username']
            password = TOML_DATA['password']
        fields.main(host=host,
                    username=username,
                    password=password,
                    name=name,
                    port=port,
                    field=field,
                    template=template)
