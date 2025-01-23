import os
import sys
import subprocess

if os.geteuid() == 0:
    #if os.path.isfile('/etc/openvpn/users') and os.path.isfile('/etc/openvpn/easy-rsa/pki'):
        print("ok")

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
            print("Certifikát úspěšně vytvořen.")
        except subprocess.CalledProcessError as e:
            print(f"Chyba při vytváření certifikátu: {e}")

   # else:
        #print("Set up OpneVPN via index.py")
else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)
