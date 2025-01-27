import os
import sys
import subprocess

def oneClient():
    clientName = input("Enter Client Name:")
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
    os.system(f"mv /etc/openvpn/easy-rsa/pki/issued/{clientName} /etc/openvpn/users/{clientName}")


    if os.path.isfile(f"/etc/openvpn/users/{clientName}"):
        os.system(f"/etc/openvpn/easy-rsa/pki/issued/{clientName}")
    else:
            print("User certificate did not copy!")
     

if os.geteuid() == 0:
    #if os.path.isfile('/etc/openvpn/users') and os.path.isfile('/etc/openvpn/easy-rsa/pki'):
        
        oneClient()
        
else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)
