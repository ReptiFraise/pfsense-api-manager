import typer
from typing import Optional
import toml
import os
import pfsense_manager.aliases as aliases
import pfsense_manager.logs as logs

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
def show_logs(host, user: Optional[str] = None, password: Optional[str] = None):
    """
    Read the vpn logs and create a file to be friendly readable
    """
    typer.echo("Logs loaded in file")
    if user is None and password is None and ISTOML == True:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        logs.get_logs_system(host=host, user=user, password=password)
    else:
        logs.get_logs_system(host=host, user=user, password=password)


def get_aliases(host,user: Optional[str] = None, password: Optional[str] = None):
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
def add_address(host, alias, ip, user: Optional[str] = None, password: Optional[str] = None):
    """
    Add an ip address or a list of ip addresses, separate addresses with comma.
    """
    if user is None and password is None and ISTOML == True:
        user = TOML_DATA['username']
        password = TOML_DATA['password']
        aliases.add_address(host=host, user=user, password=password, alias=alias, ip=ip)
    else:
        aliases.add_address(host=host, user=user, password=password, alias=alias, ip=ip)