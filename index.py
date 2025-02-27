import subprocess
import re
import os
import sys
import ipaddress


def installation():
    # stažení epel-release a openvpn
    subprocess.run(["dnf", "install", "-y", "epel-release"])
    subprocess.run(["dnf", "install", "-y", "openvpn"])


#-------------------------------------------------------------------------------------------------------------------------------------------------    

# kontrola, zda se openvpn stáhlo správně
def check_openvpn():
    try:
        result = subprocess.run(["openvpn", "--version"], text=True) #do result se vypíše, zda příkaz proběhl v pořádku
        if result.returncode == 0: #když proběhl v pořádku, tak je openvpn stažený
            print(f"OpenVPN is installed")

        #pokud se vyskytne nějaká chyba, tak se script vypne
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

#funkce načte hodnoty, poslané z vars_rewrite
def varsModify(prompt, default="NA"):
    varsValue = input(f"{prompt}: ").strip()
    #Pokud je vstup prázdný, tak vrátí hodnotu NA
    return varsValue if varsValue else default

def vars_rewrite():
    countryLetters = True
    print("\n------------ Modify vars file ------------")
    #požadavek pro hodnotu Country
    rsaCountry=input(str("Country [XX]:"))
    while countryLetters:
        charCountCountry=len(rsaCountry)
        #Počítá zda je počet znaků dva nebo nula
        if charCountCountry == 2:
            countryLetters = False
        elif charCountCountry == 0:
            rsaCountry = "NA" #Pokud je hodnota Country prázdná naství NA
            countryLetters = False
        else:
            #Pokud hodnota nesplňuje podmínky, input se objeví znovu
            print("Country must consist of two letters!")
            rsaCountry=input(str("Country [XX]:"))

    #jednotlívé hodnoty pro funkci varsModify
    rsaProvince = varsModify("Province")
    rsaCity = varsModify("City")
    rsaOrganization = varsModify("Organization")
    rsaEmail = varsModify("Email")
    rsaOu = varsModify("Organization Unit")

    #Pokud je hodnota country napsaná malým písmem jeupravena na velká písmena
    upCountry=rsaCountry.upper()

    #Cesta k souboru vars
    rsaVarsFile = "/etc/openvpn/easy-rsa/vars"

    #Hodnotz pro vložení do vars souboru skládající se z uživatelsky zadaných informací
    varsTextCounrty = f'set_var EASYRSA_REQ_COUNTRY	"{upCountry}"\n'
    varsTextProvince = f'set_var EASYRSA_REQ_PROVINCE	"{rsaProvince}"\n'
    varsTextCity = f'set_var EASYRSA_REQ_CITY	"{rsaCity}"\n'
    varsTextOrg = f'set_var EASYRSA_REQ_ORG	  "{rsaOrganization}"\n'
    varsTextEmail = f'set_var EASYRSA_REQ_EMAIL	"{rsaEmail}"\n'
    varsTextOU = f'set_var EASYRSA_REQ_OU		"{rsaOu}"\n'


    try:
        #Otevření souboru vars v režimu append
        with open(rsaVarsFile, "a") as file:
            #Zapsání proměných do souboru
            file.write(varsTextCounrty)
            file.write(varsTextProvince)
            file.write(varsTextCity)
            file.write(varsTextOrg)
            file.write(varsTextEmail)
            file.write(varsTextOU)
            file.write("#done")
        print(f"Text added to {rsaVarsFile}")
        
        #Ošetření chyb při práci se souborem
    except FileNotFoundError:
        print(f"Error: File '{rsaVarsFile}' does not exist.")
    except PermissionError:
        print(f"Error: Permission denied to write to '{rsaVarsFile}'.")
    except Exception as e:
        print(f"An error occurred: {e}")

#-------------------------------------------------------------------------------------------------------------------------------------------------

#stažení easy-rsa a příprava vars souboru
def rsa_set_up():
    os.chdir("/etc/openvpn/") #řesunutí do složky openvpn
    os.system("wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz") #stažení easy-rsa z githubu v zip souboru
    os.system("tar -xvzf EasyRSA-3.1.1.tgz") #odzipování 
    #přejmenování složky na easz-rsa a následné vymazání zipu
    os.system("mv EasyRSA-3.1.1 easy-rsa")
    os.system("rm -f /etc/openvpn/EasyRSA-3.1.1.tgz")
    #přesunutí do složky easy-rsa a přejmenování vars souboru
    os.chdir("/etc/openvpn/easy-rsa/")
    os.system("mv vars.example vars")

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Vytvoření certifikační autority
def CA_build(CA_dir):
    print("\n---------- Building new Certification Authority ----------\n")
    CA_dir = '/etc/openvpn/easy-rsa'
    os.chdir(CA_dir)
    os.system('./easyrsa init-pki') #inicializace pki
    os.system("mv /etc/openvpn/easy-rsa/vars /etc/openvpn/easy-rsa/pki/vars") #přesunutí vars do pki složky
    os.system('./easyrsa build-ca nopass') #vytvoření samotné CA

#-------------------------------------------------------------------------------------------------------------------------------------------------

#kontrola, zda se CA vytvořila
#Kontroluje se pomocí podmínky zda existuje soubor ca.crt
def CA_check():
    pathCA = "/etc/openvpn/easy-rsa/pki/ca.crt"
    if  os.path.exists(pathCA):
        print(f"CA were created successfully")
    else:
        #pokud soubor neexistuje skript skončí
        print(f"CA were NOT created successfully")
        sys.exit(1)

#-------------------------------------------------------------------------------------------------------------------------------------------------
#tvorba cerfitikátu pro server
def server_cert_gen(CA_dir, serverName):

    try:
        print("\n---------- Generating new server certificate ----------\n")
        os.chdir(CA_dir)

        #Spuštění generování s jménem, s hodnotou,k terou uživatel zadal ve složce easy-rsa
        process = subprocess.Popen(
            ["./easyrsa", "gen-req", serverName, "nopass"],
            stdin=subprocess.PIPE,
            text=True
        )

        #automaticky vyplní common name             
        process.communicate(input=f"{serverName}\n")

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, process.args)

    except subprocess.CalledProcessError as e:
        print(f"Certificate creation error: {e}")

    #podepsání certifikátu
    os.system(f'./easyrsa sign-req server {serverName}')

    #kontrola, zda byl certifikát a privátní klíč úspěšně vytvořen
    if not os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt") or not os.path.isfile(f"/etc/openvpn/easy-rsa/pki/private/{serverName}.key"):
        print("The server private key or server certificate was not successfully created!")
        sys.exit(1)

    #kopírování potřebných souborů do serverového adresáře
    os.system("cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/server/")
    os.system("cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/server/")
    os.system(f"cp /etc/openvpn/easy-rsa/pki/private/{serverName}.key /etc/openvpn/server/")
    os.system(f"cp /etc/openvpn/easy-rsa/pki/issued/{serverName}.crt /etc/openvpn/server/")

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Generování Diffie-Hellman
def server_dh_gen(CA_dir):
    print("\n---------- generating Diffie-Hellman parameter ----------\n")
    os.chdir(CA_dir)
    os.system('./easyrsa gen-dh')

#-------------------------------------------------------------------------------------------------------------------------------------------------
#tvorba logovacích souborů
def log_create():
    print("\n---------- Creating logs file ----------\n")

    logFir = False
    logSec = False

    #kontrola zda již existuje status log   
    if os.path.isfile('/var/log/ovpn-status.log'):
        print("Status log is already created")
    else:
        #pokud neexistuje tak se vytvoří
        os.system('touch /var/log/ovpn-status.log')
        logFir = True

    #kontrola zda již existuje klasický log  
    if os.path.isfile('/var/log/ovpn.log'):
        print("Clasic log is already created")
    else:
        #pokud neexistuje tak se vytvoří
        os.system('touch /var/log/ovpn.log')
        logSec = True

    if logFir == True and logSec == True:
        print("Logs files were created successfully")
        print("     /var/log/ovpn.log")
        print("     /var/log/ovpn-status.log")

#-------------------------------------------------------------------------------------------------------------------------------------------------
#tvorba jednoduché konfigurace
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
        port = input("Port number?(default openvpn 1194)").strip() #požadavek na zadání čísla portu
        if port == "": 
            #když je prázdný nastaví se na 1194
            port = "1194"
            portCheck = False
        else:
            #kontrola zda je port číslo, pokud ne vrátí se to zpět na input
            try:
                port = int(port)
                #kontrola zda se jedná o port, který existuje
                if 0 <= port <= 65535:
                    portCheck = False
                else:
                    print("Invalid port! Enter a number between 0 and 65535.")
            except ValueError:
                print("Invalid input! Please enter a valid port number.")

    #zadání a kontrola protokolu
    protocolCheck = True
    while protocolCheck:
        #zadaná hodnota se automaticky změní na malá písmena
        protocol = input("protocol? (UDP or TCP): ").strip().lower()
        if protocol == "": #pokud je hodnota prázdná, tak se vloží protokol udp
            protocol = "udp"
            print("Default UDP is set.")
            protocolCheck = False
        elif protocol in ("udp", "tcp", "udp4", "udp6", "tcp4", "tcp6"): #pokud je hodnota tcp/tcpX nebo udp/udpX tak se nechá
            protocolCheck = False
        else:
            #pokud je tam něco jiného než udp/tcp automaticky se nastaví na udp
            protocol = "udp"
            print("Invalid protocol, default UDP is set.")
            protocolCheck = False

    #zadání a kontrola interfacu
    deviceCheck = True
    while deviceCheck:
        device = input("device? (tun or tap)").strip().lower()
        if device == "": #pokud je hodnota prázdná, tak se automaticky vloží inter. tun0
            device = "tun0"
            print("Default tun0 is set.")
            deviceCheck = False
        elif device in ("tun", "tap", "tun0", "tap0"): #pokud je hodnota tun/tun0/tap/tap0, tak se ponechá
            deviceCheck = False
        else:
            #pokud je tam něco jiného ne předchozí hodnoty automaticky se nastaví tun0
            device = "tun0"
            print("Invalid device, default tun0 is set.")
            deviceCheck = False

    #zadání a kontrola rozsahu IP adres
    while networkCheck == False:
        try:
            network = input("Network (format: 'address mask'): ") #požadavek na vložení ip adresy a masky
            address, mask = network.split() #rozdělení adresy a masky
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False) #kontrolo zda je to IP adresa a maska
            networkCheck = True
        except ValueError:
            #pokud neodpovídá ip a masce požádá to znova o vyplnění
            print("Wrong format! Please enter in 'address mask' format.") 

    os.system("touch /etc/openvpn/server/server.conf") #vytvoření souboru server.conf
    with open("/etc/openvpn/server/server.conf", "a") as file: #otevtření souboru v append modu
        #vkládání jednotlivých hodnot do konfiurace
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
        file.write("topology subnet")
        file.write("status /var/log/ovpn-status.log\n")
        file.write("log /var/log/ovpn.log")

    return port, protocol, device #vrácení hodnot pro klientskou konfiguraci

#-------------------------------------------------------------------------------------------------------------------------------------------------
#tvorba konfigurace pro klienty
def usrConfEasy(port, protocol, device): #hodnoty ze serverové konfigurace

    print("\n---------- Creating client configuration ----------\n")
    #zadání ip adresy serveru
    ip = True
    while ip:
        addrHost = input("Enter server URL or IP address: ")
        try:
            # Zkontroluje, zda je zadaný text platnou IP adresou 
            ipaddress.ip_address(addrHost)
            ip = False
        except ValueError:
            #pokud ne, tak se input spustí znovu
            print(f"Invalid IP address: {addrHost}")

    os.system("sudo touch /etc/openvpn/client.ovpn") #vytvoření souboru client.ovpn
    with open("/etc/openvpn/client.ovpn", "a") as file: #otevření souboru v append modu
        #přidání hodnot do client.ovpn
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

#-------------------------------------------------------------------------------------------------------------------------------------------------

#funkce na kontrolu inputů zda je odpověĎ yes/y nebo no/n
def inputQuestion():
    check = True
    while check:
        try:
            qes = input("Type yes or no: ").strip().lower()
            if qes not in ['yes', 'no', 'y', 'n']: #kontrol zda je odpověď v špatném formátu
                raise ValueError("Invalid input. Please type 'yes' or 'no'.")
            check = False
            if qes == "yes" or qes == "y": #pokud je odpovědď yes/y tak se nastaví na y
                qes = "y"
            else: #jinka se nastaví na n
                qes = "n"
        except ValueError as e:
            print(e)
    return qes #vrácení odpovědi

#-------------------------------------------------------------------------------------------------------------------------------------------------

#požadavek na hodnotu obsahu logovacích souborů
def inputNumber():
    while True:
        try:
            #požadavek na vložení čísla
            num = int(input("Level of LOGGING [0-11]: ").strip())
            if 0 <= num <= 11: #kontrola zda je to číslo mezi 0 a 11 včetně
                return num
            else: #pokud ne opět se spustí input
                print("Number must be between 0 and 11.")
        except ValueError: #kontrolo zda se jedná o číslici
            print("Invalid input! Please enter a number between 0 and 11.")


#-------------------------------------------------------------------------------------------------------------------------------------------------

#tvorba pokročilé konfigurace pro server
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
    while portCheck == True:
        port = input("Port number?(default openvpn 1194)").strip() #požadavek na zadání čísla portu
        if port == "": 
            #když je prázdný nastaví se na 1194
            port = "1194"
            portCheck = False
        else:
            #kontrola zda je port číslo, pokud ne vrátí se to zpět na input
            try:
                port = int(port)
                #kontrola zda se jedná o port, který existuje
                if 0 <= port <= 65535:
                    portCheck = False
                else:
                    print("Invalid port! Enter a number between 0 and 65535.")
            except ValueError:
                print("Invalid input! Please enter a valid port number.")

    #zadání a kontrola protokolu
    protocolCheck = True
    while protocolCheck:
        #zadaná hodnota se automaticky změní na malá písmena
        protocol = input("protocol? (UDP or TCP): ").strip().lower()
        if protocol == "": #pokud je hodnota prázdná, tak se vloží protokol udp
            protocol = "udp"
            print("Default UDP is set.")
            protocolCheck = False
        elif protocol in ("udp", "tcp", "udp4", "udp6", "tcp4", "tcp6"): #pokud je hodnota tcp/tcpX nebo udp/udpX tak se nechá
            protocolCheck = False
        else:
            #pokud je tam něco jiného než udp/tcp automaticky se nastaví na udp
            protocol = "udp"
            print("Invalid protocol, default UDP is set.")
            protocolCheck = False

    #zadání a kontrola interfacu
    deviceCheck = True
    while deviceCheck:
        device = input("device? (tun or tap)").strip().lower()
        if device == "": #pokud je hodnota prázdná, tak se automaticky vloží inter. tun0
            device = "tun0"
            print("Default tun0 is set.")
            deviceCheck = False
        elif device in ("tun", "tap", "tun0", "tap0"): #pokud je hodnota tun/tun0/tap/tap0, tak se ponechá
            deviceCheck = False
        else:
            #pokud je tam něco jiného ne předchozí hodnoty automaticky se nastaví tun0
            device = "tun0"
            print("Invalid device, default tun0 is set.")
            deviceCheck = False

    #zadání a kontrola rozsahu IP adres
    while networkCheck == False:
        try:
            network = input("Network (format: 'address mask'): ") #požadavek na vložení ip adresy a masky
            address, mask = network.split() #rozdělení adresy a masky
            ipaddress.IPv4Network(f"{address}/{mask}", strict=False) #kontrolo zda je to IP adresa a maska
            networkCheck = True
        except ValueError:
            #pokud neodpovídá ip a masce požádá to znova o vyplnění
            print("Wrong format! Please enter in 'address mask' format.")  

    print("Do you want TLS-SERVER? [yes/no]")
    tlsServer = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné

    if device in ("tap", "tap0"): #kontrola zda inter. není tap nebo tap0 (v tomto případě není topologie potřeba)
        pass #pro tap je vždy volen device p2p
    else:
        #výběr typu topologie
        topoCheck = False
        while topoCheck == False:
            try:
                #požadavek na zadání hodnoty 1 až 3 včetně
                topology = int(input("Do you want add type of topology? (subnet[1] / net30[2] / skip[3]):"))
                if topology not in [1, 2, 3]: #pokud není správná hodnota, spustí se znovu input
                    raise ValueError("Invalid input. Please type 1 / 2 / 3 .")
                topoCheck = True
            except ValueError as errorTopo:
                print(errorTopo)

    print("Do you want allow CLIENT-TO-CLIENT communication? [yes/no]")
    ctoc = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné

    print("Do you want allow DUPLICATE-CN? [yes/no]")
    dupCN = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné

    print("Do you want PING-TIMER-REM? [yes/no]")
    pingT = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné

    verbLevl = inputNumber() #spuštění funkce pro získání hodnoty pro logování


    print("Do you want to add CIPHER [yes/no]")
    cipherUse = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné

    
    print("Do you want to redirect all trafict throught the VPN? (Full Tunnel) [yes/no]")
    redirectGateway = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné
    if redirectGateway == "y" or redirectGateway == "yes": #kontrola zda je odpověď y
        redirectGateway = "y"
        while dnsCheck: #pokud je odpověď y, spustí se input pro zadání adresy DNS 
            try:
                dns = input("DNS server address (format: 'address'): ")
                ipaddress.IPv4Network(f"{dns}", strict=False) #kontrola zda se jedná o IP adresu
                dnsCheck = False
                dnsCheckAdd = False
            except ValueError:
                print("Wrong Format! Please enter in 'address' format.")
    else:
        pass

    if device in ("tap", "tap0"): #kontrola zda se jedná o tap, jelikož tap nemá push route
        pass
    else:
        print("Do you want redirect olny a specific networks? (Split Tunnel) [yes/no]")
        lanPushUse = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné

        if lanPushUse == "y":
            pushCheck = False
            while pushCheck == False:
                try:
                    lanPush = input("Push route (format: 'address mask'): ") #rozsah adres do kterých má server vytvořit route
                    lanAddress, lanMask = lanPush.split() 
                    ipaddress.IPv4Network(f"{lanAddress}/{lanMask}", strict=False) #kontrola, zda se jedná o IP adresu a masku
                    pushCheck = True
                except ValueError:
                    print("Wrong format! Please enter in 'address mask' format.")
    
    if redirectGateway == "n": #pokud nebylo zapnuto aby všechna komunikace šla přes server, tak je možné vložit DNS
            print("Do you want ADD DNS address?")
            dnsQst = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné
            if dnsQst == "y":
                dnsCheck = True
            elif dnsQst == "No" or dnsQst == "n":
                dnsCheck = False

            while dnsCheck:
                try:
                    dns = input("DNS server address (format: 'address'): ") #požadavek pro vložení DNS adresy
                    ipaddress.IPv4Network(f"{dns}", strict=False) #kontrola zda se jedná o ip adresu
                    dnsCheck = False
                    dnsCheckAdd = True
                except ValueError:
                    print("Wrong Format! Please enter in 'address' format.")
    else:
        pass

    os.system("touch /etc/openvpn/server/server.conf") #vytvoření souboru server.conf
    with open("/etc/openvpn/server/server.conf", "a") as file: #otevření server.conf v append modu
        file.write("#Advanced configuration\n")
        #postupně se vkládají hodnoty podle uživatelsky navolených dat
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
                file.write(f"topology net30\n")
            elif topology == 3:
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

    return port, protocol, device, cipherUse, tlsServer, redirectGateway #vrácení hodnot pro využití na tvorbu konfigurace pro klienty
#-------------------------------------------------------------------------------------------------------------------------------------------------

#tvorba klientské konfiurace
def usrConfAdv(port, protocol, device, cipher, tlsServer):
    print("\n---------- Creating users configuration ----------\n")
    servRoute = False
    
    #zadání ip adresy serveru
    ip = True
    
    #zadání ip adresy serveru
    while ip:
        addrHost = input("Enter server URL or IP address: ")
        try:
            #zkontroluje, zda je zadaný text platnou IP adresou 
            ipaddress.ip_address(addrHost)
            ip = False
        except ValueError:
            #pokud ne, tak se input spustí znovu
            print(f"Invalid IP address: {addrHost}")


    os.system("touch /etc/openvpn/client.ovpn") #tvorba client.ovpn souboru pro klientskou konfiuraci
    with open("/etc/openvpn/client.ovpn", "a") as file: #otevřená client.ovpn v append modu
        #postupné přidání hodnot, dle uživatelsky zadaných informací ze serverové konfiurace
        file.write("#Advanced configuration\n")
        if tlsServer == "y":
            file.write("tls-client\n")
            file.write("pull\n")
        else:
            file.write("client\n")
        file.write(f"remote {addrHost} {port}\n")
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
        file.write("mute-replay-warnings\n")
        file.write("persist-tun\n")
        file.write("persist-key\n")
        file.write("verb 3\n")

#-------------------------------------------------------------------------------------------------------------------------------------------------

#funkce pro získání server name pro vytvoření certifikátu a privátního klíče serveru
def server_name_input():
    print("\n---------- Enter Server Name for server certificate ----------")
    Name = None
    run = True
    while run:
        if Name == "":
            print("Server name cannot be empty. Please enter a valid name.")
            Name=input("Server Name:")
        elif Name == None: #Name nesmí být prázdné
            Name=input("Server Name:")
        else:
            run = False
    return Name

#-------------------------------------------------------------------------------------------------------------------------------------------------
#nastavení potřebných oprávnění
def setRights(device):
    #nastavení vlastnictví a oprávnění pro log soubory
    os.system(f"chown openvpn:openvpn /var/log/ovpn-status.log")
    os.system(f"chown openvpn:openvpn /var/log/ovpn.log")
    os.system(f"chmod 664 /var/log/ovpn-status.log")
    os.system(f"chmod 664 /var/log/ovpn.log")
    #nastavení vlastnictví a oprávnění na interface
    device = re.sub(r'\d+', '', device)
    os.system(f"chown openvpn:openvpn /dev/net/{device}")
    os.system(f"chmod 0666 /dev/net/{device}")
    #nastavení oprávnění na složku users, kde jsou privátní klíče uživatelů
    os.system(f"chmod 770 /etc/openvpn/users/")

def setRouting():
    print("\n---------- SELinux setup and routing ----------")
    print("\nSetting SELinux permissive mode for OpenVPN.")
    #povolení ip forwardingu zapsáním do souboru sysctl.conf
    os.system('echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf')
    #nastavení selinuxu aby se pro openvpn vypnul ale stále zaznamenává jejich funkci
    os.system("semanage permissive -a openvpn_t")

#-------------------------------------------------------------------------------------------------------------------------------------------------

def serverStart():
    print("\n---------- Starting OpenVPN ----------\n") 
    os.system("systemctl restart openvpn-server@server") #restartování openvpn
    isActive = subprocess.run(["systemctl", "is-active", "openvpn-server@server"], capture_output=True, text=True) #kontrola zda je openvpn aktivní
    if isActive.stdout.strip() == "active":
        #pokud je aktivní zapne se automatické zapnutí po restartu
        os.system("systemctl enable openvpn-server@server")
        print("OpenVPN is active!")
        #os.system("systemctl status openvpn-server@server")
    else:
        print("OpenVPN could not be started. Try journalctl -xeu openvpn-server@server or start again.")
        sys.exit(1)
#-------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------     Main code     ------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------------------

if os.geteuid() == 0: #Kontroluje zda má uživatel root oprávnění
    confDone = False
    varsDone = False
    run = True
    serverName = None
    rewrite = True
    CA_dir = '/etc/openvpn/easy-rsa'
    easyrsa_path = "/usr/share/easy-rsa/3/easyrsa"

    #spouštění jednotlivých funkcí
    installation()
    check_openvpn()
    print("Both Easy-RSA and OpenVPN are installed and functioning correctly.")
    dir_struc()

    if os.path.isdir("/etc/openvpn/server") and os.path.isdir("/etc/openvpn/users"): #kontrola zda se vytvořily server a users
        rsa_set_up()
    else:
        print("/etc/openvpn/server and /etc/openvpn/users do not exist!")
        sys.exit(1)
    
    if os.path.isfile('/etc/openvpn/easy-rsa/vars'): #kontrola zda existuje soubor vars
        while rewrite:
            with open('/etc/openvpn/easy-rsa/vars', 'r') as varsFile: #pokud existuje, otevře se v read modu
                content = varsFile.read()
                if 'done' in content: #pokud obsahuje slovo done, tak skript ví, že již byl tento soubor upraven 
                    CA_build(CA_dir)
                    CA_check()
                    rewrite = False
                else:
                    #pokud neobsahuje slovo done, tak spustí vars_rewrite
                    vars_rewrite()
                    rewrite = True
    
    server_dh_gen(CA_dir)
    log_create()
    if os.path.isfile("/etc/openvpn/easy-rsa/pki/vars"): #kontrola zda se vars nachází ve složce pki
        serverName = server_name_input() #získání jména pro vytvoření certifikátů
        server_cert_gen(CA_dir, serverName)
    else:
        print("Vars file were not moved into /etc/openvpn/easy-rsa/pki/vars")
        sys.exit(1)

    #print(f"this is server name: {serverName}")
    if serverName is not None and os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt"): #kontrola zda existuje certifikát serveru a serverName není prázdný
        while run:
            #info ohledně konfigurací
            print("\n---------- Creating configuration for server ----------")
            print("Choose between easy [1] or advanced [2] configuration")
            print("Easy -> port, protocol, device, server (ip address)")
            print("Advanced -> Extended configuration")
            print("If you want to change them manually, go to /etc/openvpn/server.conf when the script is finished.")

            confCheck = True
            while confCheck:
                confQues = input("Write 1 or 2:") #požadavek pro výběr konfigurace
                if confQues.strip() == "": #kontrola zda proměná není prázdná
                    print("Invalid input! Please enter 1 or 2.")
                elif confQues == "1" or confQues == "2":
                    confCheck = False
                else:
                    print("Invalid input! Please enter 1 or 2.")


                if confQues == "1" and not os.path.isfile("/etc/openvpn/client.ovpn"): #spuštění pro jednoduchou konfiguraci
                    port, protocol, device = easyConf(serverName)
                    usrConfEasy(port, protocol, device)
                    run = False
                elif confQues == "2" and not os.path.isfile("/etc/openvpn/client.ovpn"): #spuštění pro pokročilou konfiguraci
                    port, protocol, device, cipherUse, tlsServer, redirectGateway = advancedConf(serverName)
                    usrConfAdv(port, protocol, device, cipherUse, tlsServer)
                    setRouting()
                    run = False
                else: 
                    print("Cofigurations already exist!")
                    run = False

                    
    elif serverName is None: 
        print("You must enter Server Name!")
        sys.exit(1)
    elif os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{serverName}.crt"):
        print("Server certificate was not created!")
        sys.exit(1)

    rightsDone = False
    if os.path.isfile("/var/log/ovpn.log") and os.path.isfile("/var/log/ovpn-status.log"): #kontrola zda existují logovací soubory
        setRights(device)
        rightsDone = True
    else:
        pritn("Logs file were not created!")
    
    if rightsDone: #kontrola zda se oprávnění nastavili správně
        serverStart()
    else:
        print("Something went wrong. Start from the beginning")

    print("\n---------- Certificate generation ----------")
    #možné vytvoření klientských certifikátů
    print("Do you want add users certificates?")
    usrCert = inputQuestion() #spustí se funkce na získání odpovědi y/n, a zapíše do proměné
    if usrCert == "y":
        scriptPath = os.path.dirname(os.path.abspath(__file__)) #získání cesty k index.py (create_users.py se nacházi ve stejné složce)
        os.system(f"python3 {scriptPath}/create_users.py") #spuštění create_users.pz
    else:
        print("You can add user certs via create_users.py script.")

else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)
