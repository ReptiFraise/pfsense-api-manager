from bs4 import BeautifulSoup
import paramiko
from scp import SCPClient
import os
import pfsense_manager.upload_config as upload
import pfsense_manager.reboot as rebooted


def get_file(host,
             name,
             username,
             password,
             port,
             ):
    """
    Get the file config.xml and download it in ./config/
    :param host: ip address of router
    :param name: name of the router, should be the hostname
    :param username: username to connect on ssh
    :param password: password of the user
    :param port: ssh port
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
        # copy the pcaps file from remote to local machine
        scp = SCPClient(ssh_client.get_transport())
        if os.path.isdir("./configs/"):
            print("Folder already exist")
        else:
            os.makedirs("./configs/", exist_ok=True)
        print("Actual config file will be downloaded")
        scp.get('/conf/config.xml',
                f'./configs/{name}.xml',
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


def replace_field_content(file,
                          field_name,
                          field,
                          new_file_name):
    """
    Replace the file's field with the field in parameter and write it in a new file
    :param file: file path to replace the field in
    :param field_name: field_name to search for in the xml file
    :param field: field as a BeautifulSoup tag object that will replace field in file
    :param new_file_name: new file name to create
    """
    with open(file, 'r') as file:
        content = file.readlines()
        content = "".join(content)
        soup = BeautifulSoup(content, 'xml')
        old_field = soup.find(field_name)
        old_field.replace_with(field)
        new_file = open(f"./configs/{new_file_name}", 'w')
        new_file.write(str(soup))
        new_file.close()
        file.close()


def extract_field(field_name,
                  file_with_field_configured):
    """
    Extract a field from the config.xml file and return it as a BeautifulSoup tag object
    :param field_name: The field's name you want to get
    :param file_with_field_configured: file path with the field configured
    """
    with open(file_with_field_configured, 'r') as file:
        content = file.readlines()
        content = "".join(content)
        soup = BeautifulSoup(content, 'xml')
        field = soup.find(field_name)
        file.close()
    return field


def main(host,
         name,
         port,
         username,
         password,
         field,
         template,
         reboot):
    """
    Call functions to replace fields in a config.xml file
    :param host: ip address of the router
    :param name: name of file, should be equal to th hostname
    :param port: ssh port to connect on router
    :param username: username to connect on ssh
    :param password: password of the user
    :param field: field name to replace
    :param template: file path of template to get fields in
    :param reboot: boolean, reboot the router if True
    """
    field_name = field
    new_file_name = f"new_{name}.xml"
    get_file(host=host, port=port, username=username, password=password, name=name)
    field_content = extract_field(field_name, template)
    replace_field_content(field=field_content, file=f"./configs/{name}.xml", new_file_name=new_file_name, field_name=field_name)
    print("new config file will be uploaded on router")
    upload.upload_file(host=host, name=name, username=username, password=password, port=port, file_name=f"./configs/{new_file_name}")
    if reboot is True:
        rebooted.reboot(host=host, port=port, username=username, password=password)
