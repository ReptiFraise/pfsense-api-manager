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
import pfsense_manager.reboot as reboot
import pfsense_manager.config as config
import pfsense_manager.certificates as certificates
import pfsense_manager.ca as ca
import pfsense_manager.vpn as vpn
import pfsense_manager.api as api
import pfsense_manager.packages as packages

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
    return decrypted_data.data.decode('utf-8')


def parse_json_data(json_string):
    """
    Return the content of .gpg file to json format
    :param json_strin: The content of .gpg file decrypted
    :return: A dict in json format
    """
    return json.loads(json_string)


@app.command()
def install_api(host: Optional[str] = None,
                username: Optional[str] = None,
                password: Optional[str] = None,
                port: Optional[str] = None):
    api.install_api(host=host,
                    username=username,
                    password=password,
                    port=port)


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
                    reboot: Optional[bool] = False,
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
        for data in hosts_data:
            fields.main(host=hosts_data[data],
                        username=username,
                        password=decrypted_data_dict[data],
                        name=name,
                        port=port,
                        field=field,
                        template=template,
                        reboot=reboot)
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
                    template=template,
                    reboot=reboot)


@app.command()
def reboot_router(host: Optional[str] = None,
                  port: Optional[str] = None,
                  username: Optional[str] = None,
                  password: Optional[str] = None):
    reboot.reboot(host=host,
                  port=port,
                  username=username,
                  password=password)


@app.command()
def create_config(file1_path: Optional[str] = None,
                  lan_value: Optional[str] = None,
                  hostname_value: Optional[str] = None,
                  domain_value: Optional[str] = None,
                  upload: Optional[bool] = False,
                  host: Optional[str] = None,
                  name: Optional[str] = None,
                  username: Optional[str] = None,
                  password: Optional[str] = None,
                  port: Optional[str] = None,
                  reboot: Optional[bool] = False):
    config.main(file1_path=file1_path,
                lan_value=lan_value,
                hostname_value=hostname_value,
                domain_value=domain_value,
                upload=upload,
                host=host,
                name=name,
                username=username,
                password=password,
                port=port,
                reboot=reboot)


@app.command()
def create_certificate(host: Optional[str] = None,
                      username: Optional[str] = None,
                      password: Optional[str] = None,
                      caref: Optional[str] = None,
                      description: Optional[str] = None,
                      city: Optional[str] = None,
                      commonname: Optional[str] = None,
                      country: Optional[str] = None,
                      organization: Optional[str] = None,
                      organizationalunit: Optional[str] = None,
                      state: Optional[str] = None,
                      type: Optional[str] = None):
    certificates.create_certificate(host=host,
                                    username=username,
                                    password=password,
                                    description=description,
                                    city=city,
                                    commonname=commonname,
                                    country=country,
                                    organization=organization,
                                    organizationalunit=organizationalunit,
                                    state=state,
                                    type=type,
                                    caref=caref)


@app.command()
def read_ca(host: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None):
    ca.read_ca(host=host,
               username=username,
               password=password)


@app.command()
def read_certificates(host: Optional[str] = None,
                      username: Optional[str] = None,
                      password: Optional[str] = None):
    certificates.read_certs(host=host,
                            username=username,
                            password=password)


@app.command()
def create_vpn(caref: Optional[str] = None,
               certref: Optional[str] = None,
               tls_path: Optional[str] = None,
               description: Optional[str] = None,
               host: Optional[str] = None,
               username: Optional[str] = None,
               password: Optional[str] = None,
               server_addr: Optional[str] = None,
               server_port: Optional[str] = None):
    vpn.create_vpn(caref=caref,
                   certref=certref,
                   tls_path=tls_path,
                   description=description,
                   host=host,
                   username=username,
                   password=password,
                   server_addr=server_addr,
                   server_port=server_port)


@app.command()
def add_package(host: Optional[str] = None,
                port: Optional[str] = None,
                username: Optional[str] = None,
                password: Optional[str] = None,
                package: Optional[str] = None):
    packages.add_package(host=host,
                         port=port,
                         username=username,
                         password=password,
                         package_name=package)
