from bs4 import BeautifulSoup
import pfsense_manager.upload_config as uploaded
import pfsense_manager.reboot as rebooted


def read_xml(file_path):
    """
    Read the content of xml file and returns it
    :param file_path: file path of the xml file
    """
    with open(file_path, 'r') as file:
        content = file.read()
    return content


def write_xml(file_path, content):
    """
    Write new content in the same xml file to replace values
    :param file_path: file path of the xml file
    :param content: content to write in the xml file
    """
    with open(file_path, 'w') as file:
        file.write(content)


def replace_lan_ip(xml_content, new_value):
    """
    Replace the ip address of the lan interface in the xml file
    :param xml_content: field of lan ip address
    :param new_value: new value for ip address
    """
    # Parse XML using BeautifulSoup
    soup = BeautifulSoup(xml_content, 'xml')
    # Find the field and replace its content
    field = soup.find("lan").find("ipaddr")
    if field:
        field.string = new_value
    return str(soup)


def replace_domain(xml_content, new_value):
    """
    Replace the domain name in the xml file
    :param xml_content: field of domain name
    :param new_value: new value for domain name
    """
    # Parse XML using BeautifulSoup
    soup = BeautifulSoup(xml_content, 'xml')
    # Find the field and replace its content
    field = soup.find("system").find("domain")
    if field:
        field.string = new_value
    return str(soup)


def replace_hostname(xml_content, new_value):
    """
    Replace the hostname in the xml file
    :param xml_content: field of hostname
    :param new_value: new value for hostname
    """
    # Parse XML using BeautifulSoup
    soup = BeautifulSoup(xml_content, 'xml')
    # Find the field and replace its content
    field = soup.find("system").find("hostname")
    if field:
        field.string = new_value
    return str(soup)


def main(file1_path,
         lan_value,
         hostname_value,
         domain_value,
         upload,
         host,
         name,
         username,
         password,
         port,
         reboot):
    """
    Call functions to replace the fields values in the config.xml file
    :param file1_path: config.xml file path
    :param lan_value: new value for lan ip address
    :param hostname_value: new value for hostname
    :param domain_value: new value for domain name
    :param upload: boolean, upload file on router if True
    :param host: ip address of the router to upload the file on
    :param name: name of the router, should be equal to hostname
    :param username: username of the router to upload file on
    :param password: password of the user
    :param port: ssh port of the router
    :param reboot: boolean, reboot the router if True
    """
    # Read content from file1
    file1_content = read_xml(file1_path)
    # Replace the content of the three fields
    file1_content = replace_lan_ip(file1_content, lan_value)
    file1_content = replace_hostname(file1_content, hostname_value)
    file1_content = replace_domain(file1_content, domain_value)
    # Write the modified content back to file1
    write_xml(file1_path, file1_content)
    if upload is True:
        uploaded.upload_file(host,
                             name,
                             username,
                             password,
                             port,
                             file1_path)
    if reboot is True:
        rebooted.reboot(host=host,
                        port=port,
                        username=username,
                        password=password)
