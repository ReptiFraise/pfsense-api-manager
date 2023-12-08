import typer
from typing import Optional
from typing_extensions import Annotated
import toml
import os
import pfsense_manager.aliases as aliases
import pfsense_manager.logs as pflogs

app = typer.Typer()

ISTOML = False
if os.path.isfile("./config.toml") == True:
    TOML_DATA = toml.load("./config.toml")['user']
    ISTOML = True


@app.callback()
def callback():
    """
    pfSense API management tool
    """


@app.command()
def show_logs(host: Annotated[str, typer.Argument(help="IP Address of remote pfsense")], 
              logs: Annotated[str, typer.Argument(help="system or firewall")], 
              user: Optional[str] = None, 
              password: Optional[str] = None):
    """
    Read the vpn logs and create a file to be friendly readable
    """
    typer.echo(f"{logs}")
    if user is None and password is None and ISTOML == True:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        pflogs.get_logs_system(host=host, user=user, password=password, logs=logs)
    else:
        pflogs.get_logs_system(host=host, user=user, password=password, logs=logs)

@app.command()
def get_aliases(host,
                user: Optional[str] = None, 
                password: Optional[str] = None):
    """
    Get aliases names
    """
    if user is None and password is None and ISTOML == True:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        aliases.get_aliases(host=host, user=user, password=password)
    else:
        aliases.get_aliases(host=host, user=user, password=password)


@app.command()
def add_address(host: Annotated[str, typer.Argument(help="IP Address of remote pfSense")], 
                alias: Annotated[str, typer.Argument(help="Name of the alias")], 
                ip: Annotated[str, typer.Argument(help="ip address in format : \r\t one address: x.x.x.x / list of addresses: x.x.x.x,y.y.y.y / range of addresses: x.x.x.x-y.y.y.y")], 
                user: Optional[str] = None, 
                password: Optional[str] = None):
    """
    Add an ip address or a list of ip addresses, separate addresses with comma.
    """
    if user is None and password is None and ISTOML == True:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        aliases.add_address(host=host, user=user, password=password, alias=alias, ip=ip)
    else:
        aliases.add_address(host=host, user=user, password=password, alias=alias, ip=ip)