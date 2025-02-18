import os
import sys
import subprocess
import pandas
import re

def inputQuestion():
    check = False
    while check == False:
        try:
            qes = input("Type yes or no: ").strip().lower()
            qes = qes.lower()
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

def oneClient():

    username = str(input("Enter Client Name:"))

    print("Common Name same as Client Name?")
    nameQes = inputQuestion()

    if nameQes == "y":
         
        try:
            os.chdir("/etc/openvpn/easy-rsa")
            process = subprocess.run(
                ["./easyrsa", "gen-req", username, "nopass"],
                input=f"{username}\n",
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Certificate creation error: {e}")
        
    elif nameQes == "n":
        
        commonName = input("Enter Common Name: ")

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

    createStruc(username)
    addCert(username)

    """
    os.system(f"sudo ./easyrsa sign-req client {username}")
    os.system(f"mkdir /etc/openvpn/users/{username}")

    if os.path.isfile(f"/etc/openvpn/users/{username}"):
        os.system(f"cp /etc/openvpn/easy-rsa/pki/issued/{username}.crt /etc/openvpn/users/{username}.crt")
        os.system(f"cp /etc/openvpn/easy-rsa/pki/private/{username}.key /etc/openvpn/users/{username}.key")
    else:
            print("User certificate did not copy!")
    """
    
def csvAdd():
    path = True

    while path:
        csvPath = input("Write path to a cvs file:")
        if os.path.isfile(csvPath):

            data = pandas.read_csv(csvPath, delimiter=";", encoding='utf-8')
            data = data.dropna(how='all')


            print("Common Name same as Client Name?")
            nameQes = inputQuestion()
            
            for line in data.itertuples(index=False):

                username = str(line.username).strip() if pandas.notna(line.username) and str(line.username).strip() != "" else None
                if not os.path.isdir(f"/etc/openvpn/users/{username}"):

                    if username:

                        if nameQes == "y":

                            try:
                                os.chdir("/etc/openvpn/easy-rsa")

                                process = subprocess.Popen(
                                    ["./easyrsa", "gen-req", username, "nopass"],
                                    stdin=subprocess.PIPE,
                                    text=True
                                )
                                
                                process.communicate(input=f"{username}\n")

                                if process.returncode != 0:
                                    raise subprocess.CalledProcessError(process.returncode, process.args)

                            except subprocess.CalledProcessError as e:
                                print(f"Certificate creation error: {e}")

                            createStruc(username)
                            addCert(username)
                            
                        elif nameQes == "n":
                            
                            commonName = str(input("Enter Common Name: "))

                            try:
                                os.chdir("/etc/openvpn/easy-rsa")

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
                        createStruc(username)
                        if os.path.isfile(f"/etc/openvpn/users/{username}/{username}.crt"):
                            addCert(username)
                        else:
                            print("ERROR! Certificate and key did not copied.")

                    else:
                        print("Skipping empty username")
                    path = False
                else:
                    print(f"User {username} already exist!")
                    pass
        else:
            print("This path to csv is not existing!")

def createStruc(username):
    os.system(f"sudo ./easyrsa sign-req client {username}")
    os.system(f"mkdir -p /etc/openvpn/users/{username}")

    if os.path.isdir(f"/etc/openvpn/users/{username}"):

        cmds = [
            f"sudo cp /etc/openvpn/easy-rsa/pki/issued/{username}.crt /etc/openvpn/users/{username}/{username}.crt",
            f"sudo cp /etc/openvpn/easy-rsa/pki/private/{username}.key /etc/openvpn/users/{username}/{username}.key",
            f"cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/users/{username}",
            f"cp /etc/openvpn/client.ovpn /etc/openvpn/users/{username}/client.ovpn"
        ]

        for cmd in cmds:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error: {result.stderr}")

    else:
        print("User certificates were not copied!")    

def addCert(username):
    with open(f"/etc/openvpn/users/{username}/ca.crt", "r") as sourceCA, open(f"/etc/openvpn/users/{username}/{username}.crt", "r") as sourceCrt, open(f"/etc/openvpn/users/{username}/{username}.key", "r") as sourceKey, open(f"/etc/openvpn/users/{username}/client.ovpn", "a") as usrConf:
        content = sourceCrt.read()
        userCRT = re.search(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", content, re.DOTALL)
        
        #usrConf.write("<ca>")
        #usrConf.write(sourceCA.read())
        #usrConf.write("</ca>")

        usrConf.write("<ca>\n" + sourceCA.read() + "\n</ca>\n")
        usrConf.write("<cert>\n" + userCRT.group(1) + "\n</cert>\n")
        usrConf.write("<key>\n" + sourceKey.read() + "\n</key>\n")

    
        #usrConf.write("<key>")
        #usrConf.write(sourceKey.read())
        #usrConf.write("</key>")



if os.geteuid() == 0:
    #if os.path.isfile('/etc/openvpn/users') and os.path.isfile('/etc/openvpn/easy-rsa/pki'):
        add = True
        while add:
            print("Singleuser -> 1 \nMultiuser -> 2")
            howAdd = str(input("Do you want add single user or add via csv multiuser? (1 or 2)"))

            if howAdd == "1":
                oneClient()
                add = False
            elif howAdd == "2":
                csvAdd()
                add = False
            else:
                print("Wrong value! Write 1 or 2.")
        
else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)
