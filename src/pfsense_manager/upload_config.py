import paramiko
from scp import SCPClient


def upload_file(host,
                username,
                password,
                port,
                file_name
                ):
    """
    Upload config file in /conf/ as config.xml
    :param host: ip address of the router
    :param username: username to connect on ssh
    :param password: password of the user
    :param port: ssh port
    :param file_name: path of file to upload
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
        scp = SCPClient(ssh_client.get_transport())
        scp.put(file_name,
                '/conf/config.xml',
                recursive=True)
        scp.close()
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