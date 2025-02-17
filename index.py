import glob
import subprocess
import re
import os
import sys
import ipaddress
import re

#Do you want to update DNF repository

def installation():
    #subprocess.run(["dnf", "update", "-y"])
    subprocess.run(["dnf", "install", "-y", "epel-release"])
    subprocess.run(["dnf", "install", "-y", "openvpn"])

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
"""
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
"""
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

    #for EasyRSA repository
    """
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
    """

    serverPath = "/etc/openvpn/server"
    usersPath = "/etc/openvpn/users"

    if not os.path.exists(serverPath):
        subprocess.run(["mkdir", "-p", "/etc/openvpn/server"])
    else:
        pass
    if not os.path.exists(usersPath):
        subprocess.run(["mkdir", "/etc/openvpn/users"])
    else:
        pass
    if os.path.exists(serverPath) and os.path.exists(usersPath):
        print(f"The paths '{serverPath}' and '{usersPath}' were created successfully")
    else:
        print(f"The paths '{serverPath}' and '{usersPath}' were not created successfully")
        sys.exit(1)
            
#udelat opravneni na users
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

    print("------------ Modify vars file ------------")

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

    os.chdir("/etc/openvpn/")
    os.system("wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz")
    os.system("tar -xvzf EasyRSA-3.1.1.tgz")
    os.system("mv EasyRSA-3.1.1 easy-rsa")
    os.system("rm -rf /etc/openvpn/EasyRSA-3.1.1.tgz")
    os.chdir("/etc/openvpn/easy-rsa/")
    os.system("mv vars.example vars")
    os.system("mv vars pki")

    """
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
    """

#-------------------------------------------------------------------------------------------------------------------------------------------------
def CA_build(CA_dir):
    print("\n---------- Building new Certification Authority ----------\n")
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


        try:
            print("\n---------- Generating new server certificate ----------\n")
            os.chdir("/etc/openvpn/easy-rsa")
            os.chdir(CA_dir)

            process = subprocess.Popen(
                ["./easyrsa", "gen-req", serverName, "nopass"],
                stdin=subprocess.PIPE,
                text=True
                )
                                
            process.communicate(input=f"{serverName}\nyes\n")

            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, process.args)

        except subprocess.CalledProcessError as e:
            print(f"Certificate creation error: {e}")

        os.system(f'./easyrsa sign-req server {serverName}')

def server_dh_gen(CA_dir):
    print("\n---------- generating Diffie-Hellman parameter ----------\n")
    os.chdir(CA_dir)
    os.system('./easyrsa gen-dh')

#-------------------------------------------------------------------------------------------------------------------------------------------------

def log_create():
    print("\n---------- Creating logs file ----------\n")

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

def easyConf(serverName):
    print("\n---------- Creating server configuration ----------\n")
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
        if protocol.strip() == "":
            protocol = "udp"
            protocolCheck = False
        elif protocol.lower() not in ("udp", "tcp"):
            protocol = "udp"
            protocolCheck = False
        else:
            pass
    
    deviceCheck = True
    while deviceCheck == True:
        device = input("device? (tun or tap)")
        if device.strip() == "":
            device = "tun0"
            deviceCheck = False
        elif device.lower() not in ("tun", "tap"):
            device = "tun0"
            deviceCheck = False
        else:
            pass
    
    name = str(input("Name of USER for privileges:"))
    group = str(input("Name of GROUP for privileges:"))

    while networkCheck == False:
        try:
            network = input("Network (format: 'address mask'): ")
            address, mask = network.split()
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            networkCheck = True
        except ValueError:
            print("Wrong format! Please enter in 'address mask' format.") 

    os.system("touch /etc/openvpn/server/server.conf")
    with open("/etc/openvpn/server/server.conf", "a") as file:
        file.write("#Easy configuration")
        file.write("mode server \n")
        file.write(f"port {port} \n")
        file.write(f"proto {protocol}\n")
        file.write(f"dev {device}\n")
        file.write("ca /etc/openvpn/easy-rsa/pki/ca.crt\n")
        file.write(f"cert /etc/openvpn/easy-rsa/pki/issued/{serverName}.crt\n")
        file.write(f"key /etc/openvpn/easy-rsa/pki/private/{serverName}.key\n")
        file.write("dh /etc/openvpn/easy-rsa/pki/dh.pem\n")
        file.write(f"server {network}\n")
        file.write(f"user {name}\n")
        file.write(f"group {group}\n")
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write("verb 3\n")
        file.write("status /var/log/openvpn/status.log\n")
        file.write("log /var/log/openvpn/ovpn.log")

    return port, protocol, device, name, group

#-------------------------------------------------------------------------------------------------------------------------------------------------

def usrConfEasy(port, protocol, device):
    addrHost = input("Enter server URL or IP address: ")
    protocol = re.sub(r'\d', '', protocol)

    os.system("sudo touch /etc/openvpn/client.ovpn")
    with open("/etc/openvpn/client.ovpn", "a") as file:
        file.write("#Easy configuration\n")
        #file.write("client\n")
        file.write(f"remote {addrHost} {port}\n")
        file.write(f"dev {device}\n")
        file.write(f"proto {protocol}\n")
        file.write("remote-cert-tls server\n")
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write("verb 3\n")

def inputQuestion():
    check = False
    while check == False:
        try:
            qes = input("Type yes or no: ").strip().lower()
            if qes not in ['yes', 'no', 'y', 'n']:
                raise ValueError("Invalid input. Please type 'yes' or 'no'.")
            check = True
            if qes == "yes" or qes == "y":
                qes = "y"
            else:
                pass
        except ValueError as e:
            print(e)
    return qes

def inputNumber():
    while True:
        try:
            num = int(input("Level of LOGGING [0-11]: ").strip())
            if 0 <= num <= 11:
                return num
            else:
                print("Number must be between 0 and 11.")
        except ValueError:
            print("Invalid input! Please enter a number between 0 and 11.")


#-------------------------------------------------------------------------------------------------------------------------------------------------

def advancedConf(serverName):
    port = None
    protocol = None
    device = None
    cert_dir = "/etc/openvpn/easy-rsa/pki/issued/"
    cert_file = None
    key_dir = "/etc/openvpn/easy-rsa/pki/private/"
    key_file = None
    address = None
    mask = None
    network = None
    networkCheck = False
    dnsCheck = False
    dns = None
    dnsCheckAdd = False

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
        if protocol.strip() == "":
            protocol = "udp"
            protocolCheck = False
        elif protocol.lower() not in ("udp", "tcp"):
            protocol = "udp"
            protocolCheck = False
        else:
            pass
    
    deviceCheck = True
    while deviceCheck == True:
        device = input("device? (tun or tap)")
        if device.strip() == "":
            device = "tun0"
            deviceCheck = False
        elif device.lower() not in ("tun", "tap"):
            device = "tun0"
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

    
    #question = str(input("Do you want ADD DNS address?"))
    print("Do you want ADD DNS address?")
    dnsQst = inputQuestion()
    if dnsQst == "y":
        dnsCheck = True
    elif dnsQst == "No" or dnsQst == "n":
        dnsCheck = False

    while dnsCheck:
        try:
            dns = input("DNS server address (format: 'address'): ")
            ipaddress.IPv4Network(f"{dns}", strict=False)
            dnsCheck = False
            dnsCheckAdd = True
        except ValueError:
            print("Wrong Format! Please enter in 'address' format.")

    print("Do you want TLS-SERVER?")
    #question = str(input("Do you want TLS-SERVER? (yes/no):"))
    tlsServer = inputQuestion()


    topoCheck = False
    while topoCheck == False:
        try:
            topology = int(input("Do you want add type of topology? (subnet[1] / p2p[2] / net30[3] / skip[4]):"))
            if topology not in [1, 2, 3, 4]:
                raise ValueError("Invalid input. Please type 1 / 2 / 3 / 4.")
            topoCheck = True
        except ValueError as errorTopo:
            print(errorTopo)

    print("Do you want allow CLIENT-TO-CLIENT communication?")
    #question = str(input("Do you want allow CLIENT-TO-CLIENT communication? (yes/no)"))
    ctoc = inputQuestion()

    print("Do you want allow DUPLICATE-CN? (yes/no)")
    #question = str(input("Do you want allow DUPLICATE-CN? (yes/no)"))
    dupCN = inputQuestion()

    print("Do you want PING-TIMER-REM?")
    #question = str(input("Do you want PING-TIMER-REM?  (yes/no)"))
    pingT = inputQuestion()

    name = str(input("Name of USER for privileges:"))
    group = str(input("Name of GROUP for privileges:"))

    verbLevl = inputNumber()

    print("Do you want connect VPN with internet (push-gateway)")
    #question = str(input("Do you want connect VPN with internet (push-gateway)(yes/no):"))
    gatewayUse = inputQuestion()

    print("Do you want to add CIPHER")
    #question = str(input("Do you want to add CIPHER(yes/no):"))
    cipherUse = inputQuestion()

    if gatewayUse == "y":
        gateway = '.'.join(address.split('.')[:-1]+["1"])  
    else:
        pass

    print("Do you want add some LAN (push)")
    #question = str(input("Do you want add some LAN (push)(yes/no):"))
    lanPushUse = inputQuestion()

    if lanPushUse == "yes" or lanPushUse == "y":
        pushCheck = False
        while pushCheck == False:
            try:
                lanPush = input("Push (format: 'address mask'): ")
                lanAddress, lanMask = lanPush.split()
                ipaddress.IPv4Network(f"{lanAddress}/{lanMask}", strict=False)
                pushCheck = True
            except ValueError:
                print("Wrong format! Please enter in 'address mask' format.") 

    os.system("touch /etc/openvpn/server/server.conf")
    with open("/etc/openvpn/server/server.conf", "a") as file:
        file.write("#Advanced configuration\n")
        file.write("mode server\n")
        if tlsServer == "y":
            file.write("tls-server\n")
        else:
            pass
        file.write(f"port {port} \n")
        file.write(f"proto {protocol}\n")
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
        if dnsCheckAdd == True:
            file.write(f'push "dhcp-option DNS {dns}"\n')
        else:
            pass
        if lanPushUse == "y":
            file.write(f"push {lanAddress}")
        else:
            pass
        if gatewayUse == "y":
            file.write(f"push route-gateway {gateway}")
            file.write("redirect-gateway")
        else:
            pass
        if cipherUse == "y":
            file.write("cipher AES-256-CBC\n")
            file.write("auth SHA512\n")
            file.write("tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-CBC-SHA256\n")
        else:
            pass
        if ctoc == "y":
            file.write("client-to-client\n")
        else:
            pass
        if dupCN == "y":
            file.write("duplicate-cn\n")
        else:
            pass
        if pingT == "y":
            file.write("ping-timer-rem\n")
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

    return port, protocol, device, cipherUse, gatewayUse, tlsServer, name, group

#-------------------------------------------------------------------------------------------------------------------------------------------------

def usrConfAdv(port, protocol, device, cipher, gatewayUse, tlsServer):
    print("\n---------- Creating users configuration ----------\n")
    servRoute = False
    addrHost = input("Enter server URL or IP address: ")

    if gatewayUse == "y":
        while servRoute == False:
            try:
                serverRoute = input("Route into the server (format: 'address mask'): ")
                address, mask = serverRoute.split()
                ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
                networkCheck = True
            except ValueError:
                print("Wrong format! Please enter in 'address mask' format.") 
    else:
        pass
    
    protocol = re.sub(r'\d', '', protocol)


    os.system("touch /etc/openvpn/client.ovpn")
    with open("/etc/openvpn/client.ovpn", "a") as file:
        file.write("#Easy configuration\n")
        if tlsServer == "y":
            file.write("client\n")
        else:
            pass
        file.write(f"remote {addrHost} {port}\n")
        file.write(f"dev {device}\n")
        file.write(f"proto {protocol}\n")
        file.write("redirect-gateway\n")
        file.write("resolv-retry infinite\n")
        file.write("remote-cert-tls server\n")
        if cipher == "y":
            file.write("cipher AES-256-CBC\n")
            file.write("auth SHA512\n")
            file.write("tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-CBC-SHA256\n")
        else:
            pass
        if gatewayUse == "y":
            file.write(f"route {serverRoute}\n")
        else: 
            pass
        file.write("mute-replay-warnings\n")
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write("verb 3\n")

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

def setRights(name, group, device):
    #rights for log files
    os.system(f"chown {name}:{group} /var/log/openvpn/*")
    os.system(f"chmod 644 /var/log/openvpn/*")
    #rights for device
    os.system(f"chown {name}:{group} /dev/net/{device}")
    os.system(f"chmod 0666 /dev/net/{device}")

def serverStart():
    print("\n---------- Starting OpenVPN ----------\n")
    os.system("systemctl start openvpn-server@server")
    os.system("systemctl enable openvpn-server@server")
    os.system("systemctl status openvpn-server@server")
#-------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------     Vecicky        -----------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------------------

if os.geteuid() == 0:
    run = True
    serverName = None
    CA_dir = '/etc/openvpn/easy-rsa'
    easyrsa_path = "/usr/share/easy-rsa/3/easyrsa"

    installation()
    #check_easyrsa()
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
        if serverName is None:
            print("---------- Creating configuration for server ----------")
            serverName = server_name_input()
            print("Choose between easy [1] or advanced [2] configuration")
            print("Easy -> port, protocol, device, server (ip address), log")
            print("Advanced -> Extended configuration")
            print("If you want to change them manually, after script ends go to /etc/openvpn/server.conf")

            confCheck = True
            while confCheck:
                confQues = input("Write 1 or 2:")
                if confQues.strip() == "":
                    print("Invalid input! Please enter 1 or 2.")
                elif confQues == "1" or confQues == "2":
                    confCheck = False
                else:
                    print("Invalid input! Please enter 1 or 2.")

                

            if confQues == "1":
                #easyConf(serverName)
                port, protocol, device = easyConf(serverName)
                print(f"Calling usrConfEasy with: {port}, {protocol}, {device}")
                print("podminka 1")
                usrConfEasy(port, protocol, device)
                run = False
            elif confQues == "2":
                port, protocol, device, cipher, gatewayUse, tlsServer = advancedConf(serverName)
                usrConfAdv(port, protocol, device, cipher, gatewayUse, tlsServer)
                run = False
            else:
                pass
        else:
            print("---------- Creating configuration for server ----------")
            print("Choose between easy [1] or advanced [2] configuration")
            print("Easy -> port, protocol, device, server (ip address), log")
            print("Advanced -> Extended configuration")
            print("If you want to change them manually, after script ends go to /etc/openvpn/server.conf")
            
            confCheck = True
            while confCheck:
                confQues = input("Write 1 or 2:")
                if confQues.strip() == "":
                    print("Invalid input! Please enter 1 or 2.")
                elif confQues == "1" or confQues == "2":
                    confCheck = False
                else:
                    print("Invalid input! Please enter 1 or 2.")

                
            if confQues == "1":
                #easyConf(serverName)
                port, protocol, device, name, group = easyConf(serverName)
                print(f"Calling usrConfEasy with: {port}, {protocol}, {device}")
                #usrConfEasy(port, protocol, device)
                usrConfEasy(1194, "udp", "tun0")

                run = False
            elif confQues == "2":
                port, protocol, device, cipher, gatewayUse, tlsServer, name, group = advancedConf(serverName)
                usrConfAdv(port, protocol, device, cipher, gatewayUse, tlsServer)
                run = False
            else:
                pass
    
    if os.path.exists(f"/etc/openvpn/easy-rsa/pki") and os.path.exists("/etc/openvpn/server/server.conf") and os.path.exists("/etc/openvpn/easy-rsa/pki/private/user.conf"):
        setRights(name, group, device)
        serverStart()

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
