import paramiko
from scp import SCPClient
import os


def upload_file(host,
                name,
                username,
                password,
                port
                ):
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
        scp.put(f'./configs/new_{name}.xml',
                '/conf/config2.xml',
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