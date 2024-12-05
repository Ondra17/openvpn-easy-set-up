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

def vars_rewrite(rsa_country, rsa_province, rsa_city, rsa_organization, rsa_email, rsa_ou):

    up_country=rsa_country.upper()

    char_count_country=len(rsa_country)
    if char_count_country == 2:
        rsaVarsFile = "/etc/openvpn/easy-rsa/vars"

        # Text to append
        varsTextCounrty = f'set_var EASYRSA_REQ_COUNTRY	"{rsa_country}"\n'
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
            print(f"Text added to {rsaVarsFile}")
        except FileNotFoundError:
            print(f"Error: File '{rsaVarsFile}' does not exist.")
        except PermissionError:
            print(f"Error: Permission denied to write to '{rsaVarsFile}'.")
        except Exception as e:
            print(f"An error occurred: {e}")



def CA_build():
    CA_dir = '/etc/openvpn/easy-rsa'
    os.chdir(CA_dir)
    os.system('./easyrsa init-pki')


installation()
dir_struc()
rsa_set_up()

rsa_country=input(str("Country:"))
rsa_province=input(str("Province:"))
rsa_city=input(str("City:"))
rsa_organization=input(str("Organization:"))
rsa_email=input(str("email:"))
rsa_ou=input(str("Organization Unit:"))

vars_rewrite(rsa_country, rsa_province, rsa_city, rsa_organization, rsa_email, rsa_ou)



