import os
import sys
import subprocess
import pandas
import re

#funkce na kontrolu inputů, zda je odpověď yes/y nebo no/n
def inputQuestion():
    check = True
    while check:
        try:
            qes = input("Type yes or no: ").strip().lower()
            if qes not in ['yes', 'no', 'y', 'n']: #kontrol, zda je odpověď v špatném formátu
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

#funkce na vytvoření jednoho klientského certifikátu
def oneClient():


    isUsername = True
    while isUsername:
        username = str(input("Enter Client Name:")).strip() #jméno klienta, podle toho se bude jmenovat složka a certifikát
        if username == "": #kontrola, zda je nastavena nějaká hodnota
            print("Client name must be set!")
            isUsername = True
        else:
            isUsername = False

    print("Common Name same as Client Name?") #požadavek, zda může být common name stejné jako client name
    nameQes = inputQuestion()

    #může být stejné
    if nameQes == "y": #
         
        try:
            os.chdir("/etc/openvpn/easy-rsa")
            process = subprocess.run(
                ["./easyrsa", "gen-req", username, "nopass"], #příkaz na vygenerování cklientského certifikátu
                input=f"{username}\n", #vkládá se client name na pozici common name
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Certificate creation error: {e}")
    
    #nemůže být stejné
    elif nameQes == "n":
        
        isClientName = True
        while isClientName:
            commonName = input("Enter Common Name: ").strip() #požadavek pro zadání common name
            if commonName == "": #kontrola, zda je nastavena nějaká hodnota
                print("Common name must be set!")
                isClientName = True
            else:
                isClientName = False
        

        try:
            os.chdir("/etc/openvpn/easy-rsa")
            process = subprocess.run(
                ["./easyrsa", "gen-req", username, "nopass"],
                input=f"{commonName}\n",
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Certificate creation error: {e}")

    #ověření, zda se vytvořil klíč
    if os.path.isfile(f"/etc/openvpn/easy-rsa/pki/private/{username}.key"):
        createStruc(username)
    else:
        print("The private key has not been created!")
        sys.exit(1)

    #ověření, zda se certifikát přesunul do uživatelské složky
    if os.path.isfile(f"/etc/openvpn/users/{username}/{username}.crt"):
        addCert(username)
    else:
        print("ERROR! Certificate and key did not copied.")

    
    #komprimace souborů uživatele do ZIP
    os.chdir(f"/etc/openvpn/users/{username}")
    os.system(f"zip -r ovpn_{username} *")

#-------------------------------------------------------------------------------------------------------------------------------------------------    

#přidávání uživatelů pomocí csv
def csvAdd():
    path = True

    while path:
        #požadavek pro napsání cesty k csv
        csvPath = input("Write path to a cvs file:")
        if os.path.isfile(csvPath): #kontrola, zda csv existuje

            #načtení dat z csv
            data = pandas.read_csv(csvPath, delimiter=";", encoding='utf-8')
            data = data.dropna(how='all')

            #požadavek pro stejný username jako common name
            print("Common Name same as Client Name?")
            nameQes = inputQuestion()
            
            for line in data.itertuples(index=False): #cyklus na jednotlivé řádky v csv

                #získání a úprava uživatelského jmén
                username = str(line.username).strip() if pandas.notna(line.username) and str(line.username).strip() != "" else None
                
                #kontrola, zda uživatel již existuje
                if not os.path.isdir(f"/etc/openvpn/users/{username}"):
                    if username:
                        if nameQes == "y": #pokud má být common Name stejný jako client Name

                            try:
                                os.chdir("/etc/openvpn/easy-rsa")

                                #generování žádosti o certifikát
                                process = subprocess.Popen(
                                    ["./easyrsa", "gen-req", username, "nopass"],
                                    stdin=subprocess.PIPE,
                                    text=True
                                )
                                
                                process.communicate(input=f"{username}\n") #vložení username jako common name

                                if process.returncode != 0:
                                    raise subprocess.CalledProcessError(process.returncode, process.args)

                            except subprocess.CalledProcessError as e:
                                print(f"Certificate creation error: {e}")

                            
                        elif nameQes == "n": #pokud má být commmon name zadán ručně
                            
                            isClientName = True
                            while isClientName:
                                commonName = input("Enter Common Name: ").strip() #požadavek pro zadání common name
                                if commonName == "": #kontrola, zda je nastavena nějaká hodnota
                                    print("Common name must be set!")
                                    isClientName = True
                                else:
                                    isClientName = False

                            try:
                                os.chdir("/etc/openvpn/easy-rsa")

                                #generování žádosti o certifikát
                                process = subprocess.Popen(
                                    ["./easyrsa", "gen-req", username, "nopass"],
                                    stdin=subprocess.PIPE,
                                    text=True
                                )

                                process.communicate(input=f"{commonName}\n")

                                if process.returncode != 0:
                                    raise subprocess.CalledProcessError(process.returncode, process.args)

                            except subprocess.CalledProcessError as e:
                                print(f"Certificate creation error: {e}")

                        #ověření, zda se vytvořil klíč
                        if os.path.isfile(f"/etc/openvpn/easy-rsa/pki/private/{username}.key"):
                            createStruc(username)
                        else:
                            print("The private key has not been created!")
                            sys.exit(1)

                        #ověření, zda se certifikát přesunul do uživatelské složky
                        if os.path.isfile(f"/etc/openvpn/users/{username}/{username}.crt"):
                            addCert(username)
                        else:
                            print("ERROR! Certificate and key did not copied.")
                        
                        #komprimace souborů uživatele do ZIP 
                        os.chdir(f"/etc/openvpn/users/{username}")
                        os.system(f"zip -r ovpn_{username} *")
                        
                    else:
                        print("Skipping empty username")
                    path = False
                else:
                    print(f"User {username} already exist!")
                    pass
        else:
            print("This path to csv is not existing!")

#-------------------------------------------------------------------------------------------------------------------------------------------------    

def createStruc(username):
    os.system(f"sudo ./easyrsa sign-req client {username}") #podepsání certifikátu
    if os.path.isfile(f"/etc/openvpn/easy-rsa/pki/issued/{username}.crt"):
        os.system(f"mkdir -p /etc/openvpn/users/{username}") #vytvoření složky dle uživatelsky zadaného jména
    else:
        print("User certificate has not been signed!")
        sys.exit(1)

    if os.path.isdir(f"/etc/openvpn/users/{username}"): #kontrola, zda existuje složka klienta

        
        cmds = [
            f"sudo cp /etc/openvpn/easy-rsa/pki/issued/{username}.crt /etc/openvpn/users/{username}/{username}.crt",
            f"sudo cp /etc/openvpn/easy-rsa/pki/private/{username}.key /etc/openvpn/users/{username}/{username}.key",
            f"cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/users/{username}",
            f"cp /etc/openvpn/client.ovpn /etc/openvpn/users/{username}/client.ovpn"
        ]

        #kopírování klientského cert, priv, klíče, serverového cert a klientské konfiurace (informace jsou zadány v poly cmds)
        for cmd in cmds:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error: {result.stderr}")

    else:
        print("User certificates were not copied!")    

#-------------------------------------------------------------------------------------------------------------------------------------------------    

#vkládání certifikátů a privátního klíče do konfiurace
def addCert(username):
    #otevření ca.crt, client.crt, client.key v modu read a client.ovpn v modu append
    with open(f"/etc/openvpn/users/{username}/ca.crt", "r") as sourceCA, open(f"/etc/openvpn/users/{username}/{username}.crt", "r") as sourceCrt, open(f"/etc/openvpn/users/{username}/{username}.key", "r") as sourceKey, open(f"/etc/openvpn/users/{username}/client.ovpn", "a") as usrConf:

        #vyhledání klientského certifikátu pomocí začátku a konce cetifikátu (v tomto souboru je více informaci, než pouze certifikát)
        content = sourceCrt.read()
        userCRT = re.search(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", content, re.DOTALL)

        #postupné vpisování do klientské konfigurace
        usrConf.write("<ca>\n" + sourceCA.read() + "\n</ca>\n") 
        usrConf.write("<cert>\n" + userCRT.group(1) + "\n</cert>\n")
        usrConf.write("<key>\n" + sourceKey.read() + "\n</key>\n")

#---------------------------------------------------------------------------------
#--------------------------------- Main Code -------------------------------------
#---------------------------------------------------------------------------------

isActive = subprocess.run(["systemctl", "is-active", "openvpn-server@server"], capture_output=True, text=True) #kontrola, zda je openvpn aktivní
#kontroluje, zda má uživatel rootovská oprávnění, a zda je openvpn aktivní
if os.geteuid() == 0 and isActive.stdout.strip() == "active":
    add = True
    while add:
        #výběr typu přidání uživatele

        print("\nChoose between creating only one client (1) or creating multiple users (2) via csv file")
        print("Singleuser -> 1 \nMultiuser -> 2")
        howAdd = str(input("Do you want add single user or add via csv multiuser? (1 or 2)"))

        if howAdd == "1": #Spustí přidání jednoho uživatele
            oneClient()
            add = False
        elif howAdd == "2": #Spustí přidání více uživatelů pomocí csv
            csvAdd()
            add = False
        else:
            print("Wrong value! Write 1 or 2.")
        
else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)
