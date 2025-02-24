import glob
import subprocess
import re
import os
import sys
import ipaddress
import re


def installation():
    # stažení epel-release a openvpn
    subprocess.run(["dnf", "install", "-y", "epel-release"])
    subprocess.run(["dnf", "install", "-y", "openvpn"])


#-------------------------------------------------------------------------------------------------------------------------------------------------    

# kontrola, zda se openvpn stáhlo správně
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

    #cesty k složkám pro uživatele a konfiguraci serveru
    serverPath = "/etc/openvpn/server"
    usersPath = "/etc/openvpn/users"

    if not os.path.exists(serverPath):
        #vytvoření složky pro konfiguraci serveru
        subprocess.run(["mkdir", "-p", "/etc/openvpn/server"])
    else:
        pass
    if not os.path.exists(usersPath):
        #vytvoření složky, kde budou certifikáty, klíče a kofigurace jednotlivích uživatelů
        subprocess.run(["mkdir", "/etc/openvpn/users"])
    else:
        pass
    
    #Errorové hlášky, pokud se nevytvoří složky
    if os.path.exists(serverPath) and os.path.exists(usersPath):
        print(f"The paths '{serverPath}' and '{usersPath}' were created successfully")
    else:
        print(f"The paths '{serverPath}' and '{usersPath}' were not created successfully")
        sys.exit(1)
            
#-------------------------------------------------------------------------------------------------------------------------------------------------

#funkce, které sbírá data pro soubor vars, pokud bude input prázdný vloží se NA
def varsModify(prompt, default="NA"):
    varsValue = input(f"{prompt}: ").strip()
    return varsValue if varsValue else default

def vars_rewrite():
    countryLetters = True
    print("\n------------ Modify vars file ------------")
    #input pro hodnotu Country
    rsaCountry=input(str("Country [XX]:"))
    while countryLetters:
        charCountCountry=len(rsaCountry)
        #Počítá zda je počet znaků dva nebo nula
        if charCountCountry == 2:
            countryLetters = False
        elif charCountCountry == 0:
            rsaCountry = "NA"
            countryLetters = False
        else:
            print("Country must consist of two letters!")
            rsaCountry=input(str("Country [XX]:"))

    #jednotlívé hodnoty pro funkci varsModify
    rsaProvince = varsModify("Province")
    rsaCity = varsModify("City")
    rsaOrganization = varsModify("Organization")
    rsaEmail = varsModify("Email")
    rsaOu = varsModify("Organization Unit")

    upCountry=rsaCountry.upper()


    rsaVarsFile = "/etc/openvpn/easy-rsa/vars"

    varsTextCounrty = f'set_var EASYRSA_REQ_COUNTRY	"{upCountry}"\n'
    varsTextProvince = f'set_var EASYRSA_REQ_PROVINCE	"{rsaProvince}"\n'
    varsTextCity = f'set_var EASYRSA_REQ_CITY	"{rsaCity}"\n'
    varsTextOrg = f'set_var EASYRSA_REQ_ORG	  "{rsaOrganization}"\n'
    varsTextEmail = f'set_var EASYRSA_REQ_EMAIL	"{rsaEmail}"\n'
    varsTextOU = f'set_var EASYRSA_REQ_OU		"f{rsaOu}"\n'


    try:
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
    os.system("rm -f /etc/openvpn/EasyRSA-3.1.1.tgz")
    os.chdir("/etc/openvpn/easy-rsa/")
    os.system("mv vars.example vars")

#-------------------------------------------------------------------------------------------------------------------------------------------------
def CA_build(CA_dir):
    print("\n---------- Building new Certification Authority ----------\n")
    CA_dir = '/etc/openvpn/easy-rsa'
    os.chdir(CA_dir)
    os.system('./easyrsa init-pki')
    os.system("mv /etc/openvpn/easy-rsa/vars /etc/openvpn/easy-rsa/pki/vars")
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
                                
            process.communicate(input=f"{serverName}\n")

            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, process.args)

        except subprocess.CalledProcessError as e:
            print(f"Certificate creation error: {e}")

        os.system(f'./easyrsa sign-req server {serverName}')

        if os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt") or os.path.isfile(f"/etc/openvpn/easy-rsa/pki/private/{serverName}.key"):
            pass
        else:
            print("The server private key or server certificate was not successfully created!")
            sys.exit(1)

        if os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt") and os.path.isfile(f"/etc/openvpn/easy-rsa/pki/private/{serverName}.key"):
            os.system("cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/server/")
            os.system("cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/server/")
            os.system(f"cp /etc/openvpn/easy-rsa/pki/private/{serverName}.key /etc/openvpn/server/")
            os.system(f"cp /etc/openvpn/easy-rsa/pki/issued/{serverName}.crt /etc/openvpn/server/")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def server_dh_gen(CA_dir):
    print("\n---------- generating Diffie-Hellman parameter ----------\n")
    os.chdir(CA_dir)
    os.system('./easyrsa gen-dh')

#-------------------------------------------------------------------------------------------------------------------------------------------------

def log_create():
    print("\n---------- Creating logs file ----------\n")

    logFir = False
    logSec = False
    """
    if os.path.isfile('/var/log/openvpn'):
        pass
    else:
        os.system('mkdir -p /var/log/openvpn/')
    """
    if os.path.isfile('/var/log/ovpn-status.log'):
        pass
    else:
        os.system('touch /var/log/ovpn-status.log')
        logFir = True

    if os.path.isfile('/var/log/ovpn.log'):
        pass
    else:
        os.system('touch /var/log/ovpn.log')
        logSec = True

    if logFir == True and logSec == True:
        print("Logs files were created successfully")
        print("     /var/log/ovpn.log")
        print("     /var/log/ovpn-status.log")
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
    while protocolCheck:
        protocol = input("protocol? (UDP or TCP): ").strip().lower()
        if protocol == "":
            protocol = "udp"
            print("Default UDP is set.")
            protocolCheck = False
        elif protocol in ("udp", "tcp"):
            protocolCheck = False
        else:
            protocol = "udp"
            print("Invalid protocol, default UDP is set.")
            protocolCheck = False
    
    deviceCheck = True
    while deviceCheck:
        device = input("device? (tun or tap)").strip().lower()
        if device == "":
            device = "tun0"
            print("Default tun0 is set.")
            deviceCheck = False
        elif device in ("tun", "tap", "tun0", "tap0"):
            deviceCheck = False
        else:
            device = "tun0"
            print("Invalid device, default tun0 is set.")

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
        file.write("#Easy configuration\n")
        file.write("mode server \n")
        file.write(f"port {port} \n")
        file.write(f"proto {protocol}\n")
        if device in ("tap", "tap0"):
            file.write(f"dev {device}-server\n")
        else:
            file.write(f"dev {device}\n")
        file.write("ca /etc/openvpn/server/ca.crt\n")
        file.write(f"cert /etc/openvpn/server/{serverName}.crt\n")
        file.write(f"key /etc/openvpn/server/{serverName}.key\n")
        file.write("dh /etc/openvpn/server/dh.pem\n")
        file.write(f"server {network}\n")
        file.write(f"user openvpn\n")
        file.write(f"group openvpn\n")
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write("keepalive 10 120\n")
        file.write("verb 3\n")
        file.write("status /var/log/ovpn-status.log\n")
        file.write("log /var/log/ovpn.log")

    return port, protocol, device

#-------------------------------------------------------------------------------------------------------------------------------------------------

def usrConfEasy(port, protocol, device):

    print("\n---------- Creating client configuration ----------\n")

    addrHost = input("Enter server URL or IP address: ")
    protocol = re.sub(r'\d', '', protocol)

    os.system("sudo touch /etc/openvpn/client.ovpn")
    with open("/etc/openvpn/client.ovpn", "a") as file:
        file.write("#Easy configuration\n")
        file.write("client\n")
        file.write(f"remote {addrHost} {port}\n")
        if device in ("tap", "tap0"):
            file.write(f"dev {device}-client\n")
        else:
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
                qes = "n"
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
    dnsCheck = True
    dns = None
    dnsCheckAdd = False

    portCheck = True
    while portCheck:
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
    while protocolCheck:
        protocol = input("protocol? (UDP or TCP): ").strip().lower()
        if protocol == "":
            protocol = "udp"
            print("Default UDP is set.")
            protocolCheck = False
        elif protocol in ("udp", "tcp"):
            protocolCheck = False
        else:
            protocol = "udp"
            print("Invalid protocol, default UDP is set.")
            protocolCheck = False
    
    deviceCheck = True
    while deviceCheck:
        device = input("device? (tun or tap)").strip().lower()
        if device == "":
            device = "tun0"
            print("Default tun0 is set.")
            deviceCheck = False
        elif device in ("tun", "tap", "tun0", "tap0"):
            deviceCheck = False
        else:
            device = "tun0"
            print("Invalid device, default tun0 is set.")

    while networkCheck == False:
        try:
            network = input("Network (format: 'address mask'): ")
            address, mask = network.split()
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
            networkCheck = True
        except ValueError:
            print("Wrong format! Please enter in 'address mask' format.") 


    print("Do you want TLS-SERVER? [yes/no]")
    tlsServer = inputQuestion()

    if device in ("tap", "tap0"):
        pass
    else:
        topoCheck = False
        while topoCheck == False:
            try:
                topology = int(input("Do you want add type of topology? (subnet[1] / p2p[2] / net30[3] / skip[4]):"))
                if topology not in [1, 2, 3, 4]:
                    raise ValueError("Invalid input. Please type 1 / 2 / 3 / 4.")
                topoCheck = True
            except ValueError as errorTopo:
                print(errorTopo)

    print("Do you want allow CLIENT-TO-CLIENT communication? [yes/no]")
    ctoc = inputQuestion()

    print("Do you want allow DUPLICATE-CN? [yes/no]")
    dupCN = inputQuestion()

    print("Do you want PING-TIMER-REM? [yes/no]")
    pingT = inputQuestion()

    verbLevl = inputNumber()


    print("Do you want to add CIPHER [yes/no]")
    cipherUse = inputQuestion()

    print("Do you want add specific gateway (push route-gateway)")
    gatewayUse = inputQuestion()

    if gatewayUse == "y":
        gateway = '.'.join(address.split('.')[:-1]+["1"])  
    else:
        pass

    print("Do you want to redirect all trafict throught the VPN? (Full Tunnel) [yes/no]")
    redirectGateway = inputQuestion()
    if redirectGateway == "y" or redirectGateway == "yes":
        redirectGateway = "y"
        while dnsCheck:
            try:
                dns = input("DNS server address (format: 'address'): ")
                ipaddress.IPv4Network(f"{dns}", strict=False)
                dnsCheck = False
                dnsCheckAdd = False
            except ValueError:
                print("Wrong Format! Please enter in 'address' format.")
    else:
        pass

    if device in ("tap", "tap0"):
        pass
    else:
        print("Do you want redirect olny a specific networks? (Split Tunnel) [yes/no]")
        lanPushUse = inputQuestion()

        if lanPushUse == "y":
            pushCheck = False
            while pushCheck == False:
                try:
                    lanPush = input("Push (format: 'address mask'): ")
                    lanAddress, lanMask = lanPush.split()
                    ipaddress.IPv4Network(f"{lanAddress}/{lanMask}", strict=False)
                    pushCheck = True
                except ValueError:
                    print("Wrong format! Please enter in 'address mask' format.")

    if redirectGateway == "n":
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
    else:
        pass

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
        if device in ("tap", "tap0"):
            file.write(f"dev {device}-server\n")
        else:
            file.write(f"dev {device}\n")
        file.write("ca /etc/openvpn/server/ca.crt\n")
        file.write(f"cert /etc/openvpn/server/{serverName}.crt\n")
        file.write(f"key /etc/openvpn/server/{serverName}.key\n")
        file.write("dh /etc/openvpn/server/dh.pem\n")

        if device in ("tap", "tap0"):
            pass
        else:
            if topology == 1:
                file.write(f"topology subnet\n")
            elif topology == 2:
                file.write(f"topology p2p\n")
            elif topology == 3:
                file.write(f"topology net30\n")
            elif topology == 4:
                pass
            
        file.write(f"server {network}\n")
        if dnsCheckAdd == True and redirectGateway == "n":
            file.write(f'push "dhcp-option DNS {dns}"\n')
        else:
            pass

        if device in ("tap", "tap0"):
            pass
        else:
            if lanPushUse == "y":
                file.write(f'push "route {lanPush}"\n')
            else:
                pass
            
        if gatewayUse == "y":
            file.write(f"push route-gateway {gateway}\n")
        else:
            pass
        if redirectGateway == "y" and dnsCheckAdd == False:
            file.write('push "redirect-gateway def1"\n')
            file.write(f'push "dhcp-option DNS {dns}"\n')
        else:
            pass
        if cipherUse == "y":
            file.write("data-ciphers AES-256-GCM\n")
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
        file.write(f"user openvpn\n")
        file.write(f"group openvpn\n")
        file.write("keepalive 10 120\n")
        file.write(f"verb {verbLevl}\n")
        file.write("status /var/log/ovpn-status.log\n")
        file.write("log /var/log/ovpn.log\n")

    return port, protocol, device, cipherUse, gatewayUse, tlsServer, redirectGateway
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
        file.write("#Advanced configuration\n")
        if tlsServer == "y":
            file.write("tls-client\n")
            file.write("pull\n")
        else:
            file.write("client\n")
        file.write(f"remote {addrHost} {port}\n")
        file.write(f"dev {device}\n")
        if device in ("tap", "tap0"):
            file.write(f"dev {device}-server\n")
        else:
            file.write(f"dev {device}\n")
        file.write("redirect-gateway\n")
        file.write("resolv-retry infinite\n")
        file.write("remote-cert-tls server\n")
        if cipher == "y":
            file.write("data-ciphers AES-256-GCM\n")
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
    print("\n---------- Enter Server Name for server certificate ----------")
    Name = None
    run = True
    while run == True:
        if Name == None:
            Name=input("Server Name:")
        else:
            run = False
    return Name

#-------------------------------------------------------------------------------------------------------------------------------------------------

def setRights(device):
    #rights for log files
    os.system(f"chown openvpn:openvpn /var/log/ovpn-status.log")
    os.system(f"chown openvpn:openvpn /var/log/ovpn.log")
    os.system(f"chmod 664 /var/log/ovpn-status.log")
    os.system(f"chmod 664 /var/log/ovpn.log")
    #rights for device
    device = re.sub(r'\d+', '', device)
    os.system(f"chown openvpn:openvpn /dev/net/{device}")
    os.system(f"chmod 0666 /dev/net/{device}")

def firewallRules():
    os.system('echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf')
    os.system("semanage permissive -a openvpn_t")
    print("Setting SELinux permissive mode for OpenVPN.")
    #os.system("firewall-cmd --permanent --add-service=openvpn")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def serverStart():
    print("\n---------- Starting OpenVPN ----------\n")
    os.system("systemctl restart openvpn-server@server")
    isActive = subprocess.run(["systemctl", "is-active", "openvpn-server@server"], capture_output=True, text=True)
    if isActive.stdout.strip() == "active":
        os.system("systemctl enable openvpn-server@server")
        print("OpenVPN is acive!")
        #os.system("systemctl status openvpn-server@server")
    else:
        print("OpenVPN could not be started. Try journalctl -xeu openvpn-server@server or start again.")
        sys.exit(1)
#-------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------     Main code     ------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------------------

if os.geteuid() == 0:
    confDone = False
    varsDone = False
    run = True
    serverName = None
    rewrite = True
    CA_dir = '/etc/openvpn/easy-rsa'
    easyrsa_path = "/usr/share/easy-rsa/3/easyrsa"

    installation()
    #check_easyrsa()
    check_openvpn()
    print("Both Easy-RSA and OpenVPN are installed and functioning correctly.")
    dir_struc()

    if os.path.isdir("/etc/openvpn/server") and os.path.isdir("/etc/openvpn/users"):
        rsa_set_up()
    else:
        print("/etc/openvpn/server and /etc/openvpn/users do not exist!")
        sys.exit(1)
    
    if os.path.isfile('/etc/openvpn/easy-rsa/vars'):
        while rewrite:
            with open('/etc/openvpn/easy-rsa/vars', 'r') as varsFile:
                content = varsFile.read()
                if 'done' in content:
                    CA_build(CA_dir)
                    CA_check()
                    varsDone = True
                    rewrite = False
                else:
                    vars_rewrite()
                    rewrite = True

    #CA_build(CA_dir)
    #CA_check()
    
    server_dh_gen(CA_dir)
    log_create()
    if os.path.isfile("/etc/openvpn/easy-rsa/pki/vars"):
        serverName = server_name_input()
        server_cert_gen(CA_dir, serverName)
    else:
        print("Vars file were not moved into /etc/openvpn/easy-rsa/pki/vars")
        sys.exit(1)

    print(f"this is server name: {serverName}")
    if serverName is not None and os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt"):
        while run:
            print("\n---------- Creating configuration for server ----------")
            print("Choose between easy [1] or advanced [2] configuration")
            print("Easy -> port, protocol, device, server (ip address), log")
            print("Advanced -> Extended configuration")
            print("If you want to change them manually, go to /etc/openvpn/server.conf when the script is finished.")

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
                    port, protocol, device = easyConf(serverName)
                    usrConfEasy(port, protocol, device)
                    run = False
                    confDone = True
                elif confQues == "2":
                    port, protocol, device, cipherUse, gatewayUse, tlsServer, redirectGateway = advancedConf(serverName)
                    usrConfAdv(port, protocol, device, cipherUse, gatewayUse, tlsServer)
                    firewallRules()
                    run = False
                    confDone = True
    elif serverName is None:
        print("You must enter Server Name!")
        sys.exit(1)
    elif os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt"):
        print("Server certificate was not created!")
        sys.exit(1)

    
    if os.path.isfile("/var/log/ovpn.log") and os.path.isfile("/var/log/ovpn-status.log"):
        setRights(device)
    else:
        pritn("Logs file were not created!")
    
    if varsDone and confDone:
        serverStart()
    else:
        print("Something went wrong. Start from the beginning")

    print("\n---------- Certificate generation ----------")
    print("Do you want add users certificates?")
    usrCert = inputQuestion()
    if usrCert == "y":
        scriptPath = os.path.dirname(os.path.abspath(__file__))
        os.system(f"python3 {scriptPath}/create_users.py")
    else:
        print("You can add user certs via create_users.py script.")

else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)
