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
    
    portCheck = True
    while portCheck == True:
        port = int(input("Port number?(default openvpn 1194)"))
        if port == None:
            port = "1194"
            portCheck = False
        else:
            pass

    protocolCheck = True
    while protocolCheck == True:
        protocol = input("protocol? (TCP or UDP)")
        if protocol == None:
            protocol = "udp6"
            protocolCheck = False
        elif protocol != "UDP" or protocol != "udp" or protocol != "TCP" or protocol != "tcp":
            protocol = "udp6"
            protocolCheck = False
        else:
            pass
    
    deviceCheck = True
    while deviceCheck == True:
        device = input("device? (tun or tap)")
        if device == None:
            device = "tun0"
            deviceCheck = False
        elif protocol != "TUN" or protocol != "tun" or protocol != "TAP" or protocol != "tap":
            protocol = "tun0"
            deviceCheck = False
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
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write("verb 3")
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

    portCheck = True
    while portCheck == True:
        port = int(input("Port number?(default openvpn 1194)"))
        if port == None:
            port = "1194"
            portCheck = False
        else:
            pass

    protocolCheck = True
    while protocolCheck == True:
        protocol = input("protocol? (TCP or UDP)")
        if protocol == None:
            protocol = "udp6"
            protocolCheck = False
        elif protocol != "UDP" or protocol != "udp" or protocol != "TCP" or protocol != "tcp":
            protocol = "udp6"
            protocolCheck = False
        else:
            pass
    
    deviceCheck = True
    while deviceCheck == True:
        device = input("device? (tun or tap)")
        if device == None:
            device = "tun0"
            deviceCheck = False
        elif protocol != "TUN" or protocol != "tun" or protocol != "TAP" or protocol != "tap":
            protocol = "tun0"
            deviceCheck = False
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
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write("verb 3\n")
        file.write("status /var/log/openvpn/status.log")
        file.write("log /var/log/openvpn/ovpn.log")



def inputQuestion(question):
    check = False
    while check == False:
        try:
            qes = question
            qes = qes.lower()
            if qes not in ['yes', 'no', 'y', 'n']:
                raise ValueError("Invalid input. Please type 'yes' or 'no'.")
            check = True
        except ValueError as e:
            print(e)

    return qes


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

    portCheck = True
    while portCheck == True:
        port = input("Port number?(default openvpn 1194)")
        if port.strip() == "":
            port = "1194"
            portCheck = False
        else:
            try:
                port = int(port)
                portCheck = False
            except ValueError:
                print("Invalid input! Please enter a valid port number.")

    protocolCheck = True
    while protocolCheck == True:
        protocol = input("protocol? (UDP or TCP)")
        if protocol.strip == "":
            protocol = "udp6"
            protocolCheck = False
        elif protocol != "UDP" or protocol != "udp" or protocol != "TCP" or protocol != "tcp":
            protocol = "udp6"
            protocolCheck = False
        else:
            pass
    
    deviceCheck = True
    while deviceCheck == True:
        device = input("device? (tun or tap)")
        if device.strip == "":
            device = "tun0"
            deviceCheck = False
        elif protocol != "TUN" or protocol != "tun" or protocol != "TAP" or protocol != "tap":
            protocol = "tun0"
            deviceCheck = False
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

    question = str(input("Do you want TLS-SERVER? (yes/no):"))
    tlsServer = inputQuestion(question)


    topoCheck = False
    while topoCheck == False:
        try:
            topology = int(input("Do you want add type of topology? (subnet[1] / p2p[2] / net30[3] / skip[4]):"))
            if topology not in [1, 2, 3, 4]:
                raise ValueError("Invalid input. Please type 1 / 2 / 3 / 4.")
            topoCheck = True
        except ValueError as errorTopo:
            print(errorTopo)

    question = str(input("Do you want allow CLIENT-TO-CLIENT communication? (yes/no)"))
    ctoc = inputQuestion(question)

    question = str(input("Do you want allow DUPLICATE-CN? (yes/no)"))
    dupCN = inputQuestion(question)

    question = str(input("Do you want PING-TIMER-REM?  (yes/no)"))
    pingT = inputQuestion(question)

    question = str(input("Do you want LZO COMPRESSION?  (yes/no)"))
    compLzo = inputQuestion(question)

    name = str(input("Name of USER for privileges:"))
    group = str(input("Name of GROUP for privileges:"))

    verbLevl = str(input("Level for LOGGING [0-11]: "))

    os.system("touch /etc/openvpn/server.conf")
    with open("/etc/openvpn/server.conf", "a") as file:
        file.write("#Advanced configuration\n")
        file.write("mode server\n")
        if tlsServer == "yes" or tlsServer == "y":
            file.write("tls-server\n")
        else:
            pass
        file.write(f"port {port} \n")
        file.write(f"proto {protocol}\n")
        file.write(f"proto {device}\n")
        file.write(f"dev {device}\n")
        file.write("ca /etc/openvpn/easy-rsa/pki/ca.crt\n")
        file.write(f"cert /etc/openvpn/easy-rsa/pki/issued/{serverName}.crt\n")
        file.write(f"key /etc/openvpn/easy-rsa/pki/private/{serverName}.key\n")
        file.write("dh /etc/openvpn/easy-rsa/pki/dh.pem\n")
        if topology == 1:
            file.write(f"topology subnet\n")
        elif topology == 2:
            file.write(f"topology p2p\n")
        elif topology == 3:
            file.write(f"topology net30\n")
        elif topology == 4:
            pass
        file.write(f"server {network}\n")
        if ctoc == "yes" or ctoc == "y":
            file.write("client-to-client\n")
        else:
            pass
        if dupCN == "yes" or dupCN == "y":
            file.write("duplicate-cn\n")
        else:
            pass
        if pingT == "yes" or pingT == "y":
            file.write("ping-timer-rem\n")
        else:
            pass
        if compLzo == "yes" or compLzo == "y":
            file.write("comp-lzo\n")
        else:
            pass
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write(f"user {name}\n")
        file.write(f"group {group}\n")
        file.write("keepalive 10 120\n")
        file.write(f"verb {verbLevl}\n")
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



# testovaci veci

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
"""
    tlsServeCheck = False
    while tlsServeCheck == False:
        try:
            tlsServe = str(input("Do you want TLS-SERVER? (yes/no):"))
            tlsServe = tlsServe.lower()
            if tlsServe not in ['yes', 'no', 'y', 'n']:
                raise ValueError("Invalid input. Please type 'yes' or 'no'.")
            tlsServeCheck = True
        except ValueError as errorTLS:
            print(errorTLS)
"""
