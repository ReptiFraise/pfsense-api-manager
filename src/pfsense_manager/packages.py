import paramiko


def add_package(host,
                username,
                password,
                port,
                package_name
                ):
    """
    Install package on router via sh connection
    :param host: ip address of the router
    :param username: username to connect on ssh
    :param password: password of the user
    :param port: ssh port
    :param package_name: package name to install
    """
    try:
        # Create an SSH client instance
        ssh_client = paramiko.SSHClient()
        # Automatically add the server's host key (this is insecure, use it only for testing purposes)
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Connect to the remote server
        ssh_client.connect(hostname=host,
                           port=port,
                           username=username,
                           password=password)
        stdin_, stdout_, stderr_ = ssh_client.exec_command(f"pkg install -y {package_name}")
        stdout_.channel.recv_exit_status()
        print(stdout_.channel.recv_exit_status())
        # Close the SSH connection
        ssh_client.close()
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
    except paramiko.SSHException as e:
        print(f"SSH error: {e}")
    except paramiko.BadHostKeyException as e:
        print(f"Host key error: {e}")
    except Exception as e:
        print(f"Error: {e}")
