import glob
import subprocess

#Do you want to update DNF repository

def installation():
    #subprocess.run(["dnf", "update", "-y"])
    subprocess.run(["dnf", "install", "-y", "epel-release"])
    subprocess.run(["dnf", "install", "-y", "openvpn", "easy-rsa"])

    result = subprocess.run(["openvpn", "--version"], capture_output=True, text=True)
    if result.returncode == 0:
        print("################################################")
        print("#                                              #")
        print("# OpenVPN and Easy-RSA installed successfully! #")
        print("#                                              #")
        print("################################################")
        #print(result.stdout)
    else:
        print("OpenVPN installation failed.")
        #print(result.stderr)


def dir_struc():
    subprocess.run(["mkdir", "-p", "/etc/openvpn/easy-rsa/keys"])

    #for EasyRSA repository
    subprocess.run(["mkdir", "-p", "/opt/easy-rsa"])

def rsa_set_up():

    rep_easy_rsa = glob.glob("/opt/easy-rsa/*")
    all_files = glob.glob("/usr/share/easy-rsa/3/*")
    subprocess.run(["cp", "-ai"] + all_files + ["/etc/openvpn/easy-rsa"])


    if rep_easy_rsa != None:
        subprocess.run(["rm", "-rf", "/opt/easy-rsa"])
        subprocess.run(["git", "clone", "https://github.com/OpenVPN/easy-rsa.git", "/opt/easy-rsa/"])
    else:
        subprocess.run(["git", "clone", "https://github.com/OpenVPN/easy-rsa.git", "/opt/easy-rsa/"])

    subprocess.run(["cp", "/opt/easy-rsa/easyrsa3/vars.example", "/etc/openvpn/easy-rsa/vars.example"])
    subprocess.run(["mv", "/etc/openvpn/easy-rsa/vars.example", "/etc/openvpn/easy-rsa/vars"])





installation()
dir_struc()
rsa_set_up()






#----------------------------------------------------------------------------------------------------------------------#

"""
import glob
import subprocess
import re
import os
import sys

#Do you want to update DNF repository

def installation():
    #subprocess.run(["dnf", "update", "-y"])
    subprocess.run(["dnf", "install", "-y", "epel-release"])
    subprocess.run(["dnf", "install", "-y", "openvpn", "easy-rsa"])

    result = subprocess.run(["openvpn", "--version"], capture_output=True, text=True)
    if result.returncode == 0:
        print("################################################")
        print("#                                              #")
        print("# OpenVPN and Easy-RSA installed successfully! #")
        print("#                                              #")
        print("################################################")
        #print(result.stdout)
    else:
        print("OpenVPN installation failed.")
        #print(result.stderr)


def dir_struc():
    subprocess.run(["mkdir", "-p", "/etc/openvpn/easy-rsa/keys"])
    checkKeys = "/etc/openvpn/easy-rsa/keys"
    if os.path.exists(checkKeys):
        print(f"The path '{checkKeys}' were created successfully")
    else:
        print(f"The path '{checkKeys}' were not created successfully")
        sys.exit(1)

    #for EasyRSA repository
    subprocess.run(["mkdir", "-p", "/opt/easy-rsa"])
    checkGitInstallEasy = "/opt/easy-rsa"
    if os.path.exists(checkGitInstallEasy):
        print(f"The path '{checkGitInstallEasy}' were created successfully")
    else:
        print(f"The path '{checkGitInstallEasy}' were not created successfully")
        sys.exit(1)


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

def vars_rewrite(rsa_country, rsa_province, rsa_city, rsa_organization, rsa_email):

    up_country=rsa_country.upper()

    char_count_country=len(rsa_country)
    if char_count_country == 2:
        rsaVarsFile = "/etc/openvpn/easy-rsa/vars"

        with open(rsaVarsFile, "r+") as f:
            data = f.read()
            f.seek(0)
            data = re.sub("US", up_country, data)
            data = re.sub("California", rsa_province, data)
            data = re.sub("San Francisco", rsa_city, data)
            data = re.sub("Copyleft Certificate Co", rsa_organization, data)
            data = re.sub("me@example.net", rsa_email, data)

            f.seek(0)
            f.write(data)
            f.truncate()



installation()
dir_struc()
rsa_set_up()



rsa_country=input(str("Country:"))
rsa_province=input(str("Province:"))
rsa_city=input(str("City:"))
rsa_organization=input(str("Organization:"))
rsa_email=input(str("email:"))

vars_rewrite(rsa_country, rsa_province, rsa_city, rsa_organization, rsa_email)
"""



