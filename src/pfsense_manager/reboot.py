import paramiko


def reboot(host,
           port,
           username,
           password):
    """
    Reboot the router with the command `reboot`
    :param host: ip address of router
    :param port: port for ssh connection
    :param username: user that have rights to restart router, like admin
    :param password: password of the user
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
        stdin_, stdout_, stderr_ = ssh_client.exec_command("reboot")
        stdout_.channel.recv_exit_status()
        print(stdout_.channel.recv_exit_status())
        ssh_client.close()
        print("router has been rebooted")
    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your credentials.")
    except paramiko.SSHException as e:
        print(f"SSH error: {e}")
    except paramiko.BadHostKeyException as e:
        print(f"Host key error: {e}")
    except Exception as e:
        print(f"Error: {e}")