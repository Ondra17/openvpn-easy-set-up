import glob
import subprocess
import re
import os
import sys
import ipaddress

#Do you want to update DNF repository

def installation():
    #subprocess.run(["dnf", "update", "-y"])
    subprocess.run(["dnf", "install", "-y", "epel-release"])
    subprocess.run(["dnf", "install", "-y", "openvpn", "easy-rsa"])

    easyrsa_path = "/usr/share/easy-rsa/3/easyrsa"

    """
    checkOpenVpn = subprocess.run(["openvpn", "--version"], capture_output=True, text=True)
    if checkOpenVpn.returncode == 0:
        print("################################################")
        print("#                                              #")
        print("# OpenVPN and Easy-RSA installed successfully! #")
        print("#                                              #")
        print("################################################")
        #print(result.stdout)
    else:
        print("OpenVPN installation failed.")
        #print(result.stderr) 
    """

#-------------------------------------------------------------------------------------------------------------------------------------------------

def check_easyrsa(easyrsa_path):
    try:
        if not os.path.isfile(easyrsa_path):
            print(f"Easy-RSA script not found at {easyrsa_path}. Please check your installation.")
            sys.exit(1)

        result = subprocess.run([easyrsa_path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            print(f"Easy-RSA is installed and available")
        else:
            print(f"Easy-RSA command failed:\n{result.stderr.strip()}")
            sys.exit(1) 
    except Exception as e:
        print(f"An error occurred while checking Easy-RSA: {e}")
        sys.exit(1)  

#-------------------------------------------------------------------------------------------------------------------------------------------------

def check_openvpn():
    try:
        result = subprocess.run(["openvpn", "--version"], text=True)
        if result.returncode == 0:
            print(f"OpenVPN is installed")
        else:
            print(f"OpenVPN command failed")
            sys.exit(1)
    except FileNotFoundError:
        print("OpenVPN is NOT installed or NOT in the PATH.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while checking OpenVPN: {e}")
        sys.exit(1)  

#-------------------------------------------------------------------------------------------------------------------------------------------------

def dir_struc():
    if  os.path.exists("/etc/openvpn/easy-rsa/keys"):
        pass
    else:
        subprocess.run(["mkdir", "-p", "/etc/openvpn/easy-rsa/keys"])
        checkKeys = "/etc/openvpn/easy-rsa/keys"
        if os.path.exists(checkKeys):
            print(f"The path '{checkKeys}' were created successfully")
        else:
            print(f"The path '{checkKeys}' were not created successfully")
            sys.exit(1)

    #for EasyRSA repository
    checkGitInstallEasy = "/opt/easy-rsa"
    if  os.path.exists(checkGitInstallEasy):
        pass
    else:
        subprocess.run(["mkdir", "-p", "/opt/easy-rsa"])
        if os.path.exists(checkGitInstallEasy):
            print(f"The path '{checkGitInstallEasy}' were created successfully")
        else:
            print(f"The path '{checkGitInstallEasy}' were not created successfully")
            sys.exit(1)

#-------------------------------------------------------------------------------------------------------------------------------------------------
"""
def rsa_qes():
    rsa_country=input(str("Country:"))
    rsa_province=input(str("Province:"))
    rsa_city=input(str("City:"))
    rsa_organization=input(str("Organization:"))
    rsa_email=input(str("email:"))
    rsa_ou=input(str("Organization Unit:"))

    return rsa_city, rsa_country, rsa_email, rsa_organization, rsa_province, rsa_ou
"""
#-------------------------------------------------------------------------------------------------------------------------------------------------

def vars_rewrite():

    rsa_country=input(str("Country:"))
    rsa_province=input(str("Province:"))
    rsa_city=input(str("City:"))
    rsa_organization=input(str("Organization:"))
    rsa_email=input(str("email:"))
    rsa_ou=input(str("Organization Unit:"))

    up_country=rsa_country.upper()

    char_count_country=len(rsa_country)
    if char_count_country == 2:
        rsaVarsFile = "/etc/openvpn/easy-rsa/vars"

        # Text to append
        varsTextCounrty = f'set_var EASYRSA_REQ_COUNTRY	"{up_country}"\n'
        varsTextProvince = f'set_var EASYRSA_REQ_PROVINCE	"{rsa_province}"\n'
        varsTextCity = f'set_var EASYRSA_REQ_CITY	"{rsa_city}"\n'
        varsTextOrg = f'set_var EASYRSA_REQ_ORG	  "{rsa_organization}"\n'
        varsTextEmail = f'set_var EASYRSA_REQ_EMAIL	"{rsa_email}"\n'
        varsTextOU = f'set_var EASYRSA_REQ_OU		"f{rsa_ou}"\n'


        try:
            # Open the file in append mode
            with open(rsaVarsFile, "a") as file:
                file.write(varsTextCounrty)
                file.write(varsTextProvince)
                file.write(varsTextCity)
                file.write(varsTextOrg)
                file.write(varsTextEmail)
                file.write(varsTextOU)
                file.write("#done")
            print(f"Text added to {rsaVarsFile}")
        except FileNotFoundError:
            print(f"Error: File '{rsaVarsFile}' does not exist.")
        except PermissionError:
            print(f"Error: Permission denied to write to '{rsaVarsFile}'.")
        except Exception as e:
            print(f"An error occurred: {e}")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def rsa_set_up():

    rep_easy_rsa = glob.glob("/opt/easy-rsa/*")
    all_files = glob.glob("/usr/share/easy-rsa/3/*")
    subprocess.run(["cp", "-ai"] + all_files + ["/etc/openvpn/easy-rsa/"])
    #cp /usr/share/easy-rsa/3/* /etc/openvpn/easy-rsa/


    if rep_easy_rsa != None:
        subprocess.run(["rm", "-rf", "/opt/easy-rsa"])
        subprocess.run(["git", "clone", "https://github.com/OpenVPN/easy-rsa.git", "/opt/easy-rsa/"])
    else:
        subprocess.run(["git", "clone", "https://github.com/OpenVPN/easy-rsa.git", "/opt/easy-rsa/"])

    subprocess.run(["cp", "/opt/easy-rsa/easyrsa3/vars.example", "/etc/openvpn/easy-rsa/vars.example"])
    subprocess.run(["mv", "/etc/openvpn/easy-rsa/vars.example", "/etc/openvpn/easy-rsa/vars"])

#-------------------------------------------------------------------------------------------------------------------------------------------------
def CA_build(CA_dir):
    CA_dir = '/etc/openvpn/easy-rsa'
    os.chdir(CA_dir)
    os.system('./easyrsa init-pki')
    os.system('./easyrsa build-ca nopass')

#-------------------------------------------------------------------------------------------------------------------------------------------------

def CA_check():

    pathCA = "/etc/openvpn/easy-rsa/pki/ca.crt"
    if  os.path.exists(pathCA):
        print(f"CA were created successfully")
    else:
        print(f"CA were NOT created successfully")
        sys.exit(1)

#-------------------------------------------------------------------------------------------------------------------------------------------------

def server_cert_gen(CA_dir, serverName):

        os.chdir(CA_dir)
        os.system(f'./easyrsa gen-req {serverName} nopass')
        os.system(f'./easyrsa sign-req server {serverName}')

def server_dh_gen(CA_dir):

        os.chdir(CA_dir)
        os.system('./easyrsa gen-dh')

#-------------------------------------------------------------------------------------------------------------------------------------------------

def log_create():

    logFir = False
    logSec = False

    if os.path.isfile('/var/log/openvpn/'):
        pass
    else:
        os.system('mkdir -p /var/log/openvpn/')

    if os.path.isfile('/var/log/openvpn/status.log'):
        pass
    else:
        os.system('touch /var/log/openvpn/status.log')
        logFir = True

    if os.path.isfile('/var/log/openvpn/ovpn.log'):
        pass
    else:
        os.system('touch /var/log/openvpn/ovpn.log')
        logSec = True

    if logFir == True and logSec == True:
        print("Logs files were created successfully")
    else:
        print("Logs files are already created")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def openVpnConf(serverName):
    port = None
    protocol = None
    device = None
    cert_dir = "/etc/openvpn/easy-rsa/pki/issued/"
    cert_file = None
    key_dir = "/etc/openvp/easy-rsa/pki/private/"
    key_file = None
    address = None
    mask = None
    check = None
    network = None
    networkCheck = False
    
    port = int(input("Port number?(default openvpn 1194)"))
    if port == None:
        port = "1194"
    else:
        pass

    protocol = input("protocol? (TCP or UDP)")
    if protocol == None:
        protocol = "udp6"
    elif protocol != "UDP" or protocol != "udp" or protocol != "TCP" or protocol != "tcp":
        protocol = "udp6"
    else:
        pass

    device = input("device? (tun or tap)")
    if device == None:
        device = "tun0"
    elif protocol != "TUN" or protocol != "tun" or protocol != "TAP" or protocol != "tap":
        protocol = "tun0"
    else:
        pass

    while networkCheck == False:
        try:
            network = input("Network (format: 'address mask'): ")
            address, mask = network.split()
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            networkCheck = True
        except ValueError:
            print("Wrong format! Please enter in 'address mask' format.")
    
    """
    for root, _, files in os.walk(cert_dir):
        for file in files:
            if file.endswith(".crt"):
                cert_file = os.path.join(root, file)
                break  # Nalezený certifikát, ukončíme hledání
    
    for root, _, files in os.walk(key_dir):
        for file in files:
            if file == "ca.key":
                continue
            if file.endswith(".key"):
                key_file = os.path.join(root, file)
                break 
    """      

    os.system("touch /etc/openvpn/server.conf")
    with open("/etc/openvpn/server.conf", "a") as file:
        file.write("mode server")
        file.write(f"port {port} \n")
        file.write(f"proto {protocol}\n")
        file.write(f"proto {device}\n")
        file.write(f"dev {device}\n")
        file.write("ca /etc/openvpn/easy-rsa/pki/ca.crt\n")
        file.write(f"cert /etc/openvpn/easy-rsa/pki/issued/{serverName}.crt\n")
        file.write(f"key /etc/openvpn/easy-rsa/pki/private/{serverName}.key\n")
        file.write("dh /etc/openvpn/easy-rsa/pki/dh.pem\n")
        file.write(f"server {network}\n")
        file.write("keepalive 10 120\n")
        file.write("status /var/log/openvpn/status.log")
        file.write("log /var/log/openvpn/ovpn.log")
        #os.system("cp /usr/share/doc/openvpn/sample/sample-config-files/server.conf /etc/openvpn")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def easyConf(serverName):
    port = None
    protocol = None
    device = None
    cert_dir = "/etc/openvpn/easy-rsa/pki/issued/"
    cert_file = None
    key_dir = "/etc/openvp/easy-rsa/pki/private/"
    key_file = None
    address = None
    mask = None
    network = None
    networkCheck = False

    port = int(input("Port number?(default openvpn 1194)"))
    if port == None:
        port = "1194"
    else:
        pass

    protocol = input("protocol? (TCP or UDP)")
    if protocol == None:
        protocol = "udp6"
    elif protocol != "UDP" or protocol != "udp" or protocol != "TCP" or protocol != "tcp":
        protocol = "udp6"
    else:
        pass

    device = input("device? (tun or tap)")
    if device == None:
        device = "tun0"
    elif protocol != "TUN" or protocol != "tun" or protocol != "TAP" or protocol != "tap":
        protocol = "tun0"
    else:
        pass

    while networkCheck == False:
        try:
            network = input("Network (format: 'address mask'): ")
            address, mask = network.split()
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            networkCheck = True
        except ValueError:
            print("Wrong format! Please enter in 'address mask' format.")

    os.system("touch /etc/openvpn/server.conf")
    with open("/etc/openvpn/server.conf", "a") as file:
        file.write("#Easy configuration")
        file.write("mode server")
        file.write(f"port {port} \n")
        file.write(f"proto {protocol}\n")
        file.write(f"dev {device}\n")
        file.write("ca /etc/openvpn/easy-rsa/pki/ca.crt\n")
        file.write(f"cert /etc/openvpn/easy-rsa/pki/issued/{serverName}.crt\n")
        file.write(f"key /etc/openvpn/easy-rsa/pki/private/{serverName}.key\n")
        file.write("dh /etc/openvpn/easy-rsa/pki/dh.pem\n")
        file.write(f"server {network}\n")
        file.write("status /var/log/openvpn/status.log")
        file.write("log /var/log/openvpn/ovpn.log")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def advancedConf(serverName):
    port = None
    protocol = None
    device = None
    cert_dir = "/etc/openvpn/easy-rsa/pki/issued/"
    cert_file = None
    key_dir = "/etc/openvp/easy-rsa/pki/private/"
    key_file = None
    address = None
    mask = None
    network = None
    networkCheck = False

    port = int(input("Port number?(default openvpn 1194)"))
    if port == None:
        port = "1194"
    else:
        pass

    protocol = input("protocol? (TCP or UDP)")
    if protocol == None:
        protocol = "udp6"
    elif protocol != "UDP" or protocol != "udp" or protocol != "TCP" or protocol != "tcp":
        protocol = "udp6"
    else:
        pass

    device = input("device? (tun or tap)")
    if device == None:
        device = "tun0"
    elif protocol != "TUN" or protocol != "tun" or protocol != "TAP" or protocol != "tap":
        protocol = "tun0"
    else:
        pass

    while networkCheck == False:
        try:
            network = input("Network (format: 'address mask'): ")
            address, mask = network.split()
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            networkCheck = True
        except ValueError:
            print("Wrong format! Please enter in 'address mask' format.") 

    topology = None

    os.system("touch /etc/openvpn/server.conf")
    with open("/etc/openvpn/server.conf", "a") as file:
        file.write("#Advanced configuration\n")
        file.write("mode server\n")
        file.write("tls-server\n")    #zeptat
        file.write(f"port {port} \n")
        file.write(f"proto {protocol}\n")
        file.write(f"proto {device}\n")
        file.write(f"dev {device}\n")
        file.write("ca /etc/openvpn/easy-rsa/pki/ca.crt\n")
        file.write(f"cert /etc/openvpn/easy-rsa/pki/issued/{serverName}.crt\n")
        file.write(f"key /etc/openvpn/easy-rsa/pki/private/{serverName}.key\n")
        file.write("dh /etc/openvpn/easy-rsa/pki/dh.pem\n")
        file.write(f"topology {topology}\n") #zeptat
        file.write(f"server {network}\n")
        file.write("client-to-client\n")    #zeptat
        file.write("duplicate-cn\n")    #zeptat
        file.write("ping-timer-rem\n")    #zeptat
        file.write("comp-lzo\n")    #zeptat
        file.write("verb 3\n")    #zeptat
        file.write("persist-tun\n")    #zeptat
        file.write("persist-key\n")    #zeptat
        file.write("user openvpn\n")    #zeptat
        file.write("group openvpn\n")    #zeptat
        file.write("keepalive 10 120\n")
        file.write("status /var/log/openvpn/status.log\n")
        file.write("log /var/log/openvpn/ovpn.log\n")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def server_name_input():
        Name = None
        run = True
        while run == True:
            if Name == None:
                Name=input("Server Name:")
            else:
                run = False
        return Name
#-------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------     Vecicky        -----------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------------------

if os.geteuid() == 0:
    run = True
    serverName = None
    CA_dir = '/etc/openvpn/easy-rsa'
    easyrsa_path = "/usr/share/easy-rsa/3/easyrsa"

    installation()
    check_easyrsa(easyrsa_path)
    check_openvpn()
    print("Both Easy-RSA and OpenVPN are installed and functioning correctly.")
    dir_struc()
  
    if os.path.isfile('/etc/openvpn/easy-rsa/vars'):
        with open('/etc/openvpn/easy-rsa/vars', 'r') as varsFile:
            content = varsFile.read()
            if 'done' in content:
                pass
            else:
                rsa_set_up()
                vars_rewrite()
                
    else:
        rsa_set_up()
        vars_rewrite()
        

    if os.path.exists("/etc/openvpn/easy-rsa/pki/ca.crt"): 
        pass
    else:   
        CA_build(CA_dir)
    

    if serverName == None:
        if  os.path.exists(f"/etc/openvpn/easy-rsa/pki/private/{serverName}.key") and os.path.exists(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt"):
            pass
        else:
            serverName = server_name_input()
            server_cert_gen(CA_dir, serverName)
    else:
        pass

    if  os.path.exists("/etc/openvpn/easy-rsa/pki/dh.pem"):
        pass
    else:
        server_dh_gen(CA_dir)

    log_create()
    """
    if serverName == None:
        serverName = server_name_input()
        openVpnConf(serverName)
    else:
        openVpnConf(serverName)
    """
    #Easy installation or advanced
    while run == True:
        if serverName == None:
            serverName = server_name_input()
            print("Choose between easy [1] or advanced [2] configuration")
            print("Easy -> port, protocol, device, server (ip address), log")
            print("Advanced -> Extended configuration")
            print("If you want to change them manually, after script ends go to /etc/openvpn/server.conf")
            confQues = int(input("Write 1 or 2:"))

            if confQues == 1:
                easyConf(serverName)
                run = False
            elif confQues == 2:
                advancedConf(serverName)
                run = False
            else:
                pass
        else:
            print("Choose between easy [1] or advanced [2] configuration")
            print("Easy -> port, protocol, device, server (ip address), log")
            print("Advanced -> Extended configuration")
            print("If you want to change them manually, after script ends go to /etc/openvpn/server.conf")
            confQues = int(input("Write 1 or 2:"))

            if confQues == 1:
                easyConf(serverName)
                run = False
            elif confQues == 2:
                advancedConf(serverName)
                run = False
            else:
                pass


else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)



