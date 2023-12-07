import typer

app = typer.Typer()


@app.callback()
def callback():
    """
    pfSense API management tool
    """


@app.command()
def show_logs(host, user, password):
    """
    Read the vpn logs and create a file to be friendly readable
    """
    typer.echo("Logs loaded in file")