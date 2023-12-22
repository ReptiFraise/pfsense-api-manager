import nox


@nox.session()
def install(session):
    session.install("flit")
    session.run("flit", "install", "--deps", "production")


@nox.session()
def doc(session):
    session.install("flit")
    session.run("flit", "install", "--deps", "production")
