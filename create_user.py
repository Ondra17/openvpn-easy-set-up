import os
import sys
import subprocess
import pandas
import re

def inputQuestion(question):
    check = False
    while check == False:
        try:
            qes = question
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

    clientName = str(input("Enter Client Name:"))

    question = str(input("Common Name same as Client Name (yes/no):"))
    nameQes = inputQuestion(question)

    if nameQes == "y":
         
        try:
            os.chdir("/etc/openvpn/easy-rsa")
            process = subprocess.run(
                ["./easyrsa", "gen-req", clientName, "nopass"],
                input=f"{clientName}\n",
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
                ["./easyrsa", "gen-req", clientName, "nopass"],
                input=f"{commonName}\n",
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Certificate creation error: {e}")



    os.system(f"sudo ./easyrsa sign-req client {clientName}")
    os.system(f"mkdir /etc/openvpn/users/{clientName}")

    if os.path.isfile(f"/etc/openvpn/users/{clientName}"):
        os.system(f"cp /etc/openvpn/easy-rsa/pki/issued/{clientName}.crt /etc/openvpn/users/{clientName}.crt")
        os.system(f"cp /etc/openvpn/easy-rsa/pki/private/{clientName}.key /etc/openvpn/users/{clientName}.key")
    else:
            print("User certificate did not copy!")

def csvAdd():
    path = True

    while path:
        csvPath = input("Write path to a cvs file:")
        if os.path.isfile(csvPath):

            data = pandas.read_csv(csvPath, delimiter=";", encoding='utf-8')
            data = data.dropna(how='all')


            
            question = str(input("Common Name same as Client Name (yes/no):"))
            nameQes = inputQuestion(question)
            
            for line in data.itertuples(index=False):

                username = str(line.username).strip() if pandas.notna(line.username) and str(line.username).strip() != "" else None

                if username:

                    if nameQes == "y":
                        
                        try:
                            os.chdir("/etc/openvpn/easy-rsa")

                            process = subprocess.Popen(
                                ["./easyrsa", "gen-req", username, "nopass"],
                                stdin=subprocess.PIPE,
                                text=True
                            )
                            
                            process.communicate(input=f"{username}\nyes\n")

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
                    addCert(username)


                else:
                    print("Skipping empty username")
                path = False
        else:
            print("This path to csv is not existing!")

def createStruc(username):
    os.system(f"sudo ./easyrsa sign-req client {username}")
    os.system(f"sudo mkdir /etc/openvpn/users/{username}")

    if os.path.isfile(f"/etc/openvpn/users/{username}"):
        os.system(f"sudo cp /etc/openvpn/easy-rsa/pki/issued/{username}.crt /etc/openvpn/users/{username}.crt")
        os.system(f"sudo cp /etc/openvpn/easy-rsa/pki/private/{username}.key /etc/openvpn/users/{username}.key")
        print("User certificate were created successfully")
        os.system(f"cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/users/{username}")
        os.system(f"cp /etc/openvpn/user.ovpn /etc/openvpn/users/{username}")
        
    else:
        print("User certificate did not copy!")    

def addCert(username):
    with open(f"/etc/openvpn/users/{username}/ca.crt", "r") as sourceCA, open(f"/etc/openvpn/users/{username}/{username}.key", "r") as sourceKey, open(f"/etc/openvpn/users/{username}/{username}.ovpn", "a") as usrFile:
        usrFile.write("<ca>")
        usrFile.write(sourceCA.read())
        usrFile.write("</ca>")

        usrFile.write("<key>")
        usrFile.write(sourceKey.read())
        usrFile.write("</key>")



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
