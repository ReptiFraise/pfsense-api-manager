from bs4 import BeautifulSoup
import pfsense_manager.upload_config as uploaded
import pfsense_manager.reboot as rebooted


def read_xml(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content


def write_xml(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)


def replace_lan_ip(xml_content, new_value):
    # Parse XML using BeautifulSoup
    soup = BeautifulSoup(xml_content, 'xml')
    # Find the field and replace its content
    field = soup.find("lan").find("ipaddr")
    if field:
        field.string = new_value
    return str(soup)


def replace_domain(xml_content, new_value):
    # Parse XML using BeautifulSoup
    soup = BeautifulSoup(xml_content, 'xml')
    # Find the field and replace its content
    field = soup.find("system").find("domain")
    if field:
        field.string = new_value
    return str(soup)


def replace_hostname(xml_content, new_value):
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
         file_name,
         reboot):
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
