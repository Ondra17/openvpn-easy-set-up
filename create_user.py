import os
import sys
import subprocess
import pandas

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
            print(f"Chyba při vytváření certifikátu: {e}")
        
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
            print(f"Chyba při vytváření certifikátu: {e}")



    os.system(f"sudo ./easyrsa sign-req client {clientName}")
    os.system(f"mkdir /etc/openvpn/users/{clientName}")

    if os.path.isfile(f"/etc/openvpn/users/{clientName}"):
        os.system(f"mv /etc/openvpn/easy-rsa/pki/issued/{clientName}.crt /etc/openvpn/users/{clientName}.crt")
        os.system(f"mv /etc/openvpn/easy-rsa/pki/private/{clientName}.key /etc/openvpn/users/{clientName}.key")
    else:
            print("User certificate did not copy!")

def csvAdd():
    data = pandas.read_csv('create_cert.csv', delimiter=";", encoding='utf-8')
    data = data.dropna(how='all')

    idx = 0
    
    for index, line in data.iterrows():
        idx += 1

        print(f'{idx}. -->')

        username = str(line['username']).strip() if pandas.notna(line['username']) and str(line['username']).strip() != "" else None

        if username:
            
            question = str(input("Common Name same as Client Name (yes/no):"))
            nameQes = inputQuestion(question)

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
                    print(f"Chyba při vytváření certifikátu: {e}")
                
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
                    print(f"Chyba při vytváření certifikátu: {e}")



            os.system(f"sudo ./easyrsa sign-req client {username}")
            os.system(f"mkdir /etc/openvpn/users/{username}")

            if os.path.isfile(f"/etc/openvpn/users/{username}"):
                os.system(f"mv /etc/openvpn/easy-rsa/pki/issued/{username}.crt /etc/openvpn/users/{username}.crt")
                os.system(f"mv /etc/openvpn/easy-rsa/pki/private/{username}.key /etc/openvpn/users/{username}.key")
            else:
                    print("User certificate did not copy!")

        else:
            print("Skipping empty username")

        




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
