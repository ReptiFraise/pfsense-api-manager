import typer

app = typer.Typer()


@app.callback()
def callback():
    """
    pfSense API management tool
    """

@app.command()
def add_address(ip):
    """
    Add an ip address or a list of ip addresses, separate addresses with comma.
    """
    if ip.count(",") >= 1:
        typer.echo(f"IP addresses {ip} added")
    else:
        typer.echo(f"IP address {ip} added")


@app.command()
def read_vpn_logs():
    """
    Read the vpn logs and create a file to be friendly readable
    """
    typer.echo("Logs loaded in file")