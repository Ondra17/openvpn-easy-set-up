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

    easyrsa_path = "/usr/share/easy-rsa/3/easyrsa"

    """
    checkOpenVpn = subprocess.run(["openvpn", "--version"], capture_output=True, text=True)
    if checkOpenVpn.returncode == 0:
        print("################################################")
        print("#                                              #")
        print("# OpenVPN and Easy-RSA installed successfully! #")
        print("#                                              #")
        print("################################################")
        #print(result.stdout)
    else:
        print("OpenVPN installation failed.")
        #print(result.stderr) 
    """

#-------------------------------------------------------------------------------------------------------------------------------------------------

def check_easyrsa(easyrsa_path):
    try:
        if not os.path.isfile(easyrsa_path):
            print(f"Easy-RSA script not found at {easyrsa_path}. Please check your installation.")
            sys.exit(1)

        result = subprocess.run([easyrsa_path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            print(f"Easy-RSA is installed and available")
        else:
            print(f"Easy-RSA command failed:\n{result.stderr.strip()}")
            sys.exit(1) 
    except Exception as e:
        print(f"An error occurred while checking Easy-RSA: {e}")
        sys.exit(1)  

#-------------------------------------------------------------------------------------------------------------------------------------------------

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
    if  os.path.exists("/etc/openvpn/easy-rsa/keys"):
        pass
    else:
        subprocess.run(["mkdir", "-p", "/etc/openvpn/easy-rsa/keys"])
        checkKeys = "/etc/openvpn/easy-rsa/keys"
        if os.path.exists(checkKeys):
            print(f"The path '{checkKeys}' were created successfully")
        else:
            print(f"The path '{checkKeys}' were not created successfully")
            sys.exit(1)

    #for EasyRSA repository
    checkGitInstallEasy = "/opt/easy-rsa"
    if  os.path.exists(checkGitInstallEasy):
        pass
    else:
        subprocess.run(["mkdir", "-p", "/opt/easy-rsa"])
        if os.path.exists(checkGitInstallEasy):
            print(f"The path '{checkGitInstallEasy}' were created successfully")
        else:
            print(f"The path '{checkGitInstallEasy}' were not created successfully")
            sys.exit(1)

#-------------------------------------------------------------------------------------------------------------------------------------------------
"""
def rsa_qes():
    rsa_country=input(str("Country:"))
    rsa_province=input(str("Province:"))
    rsa_city=input(str("City:"))
    rsa_organization=input(str("Organization:"))
    rsa_email=input(str("email:"))
    rsa_ou=input(str("Organization Unit:"))

    return rsa_city, rsa_country, rsa_email, rsa_organization, rsa_province, rsa_ou
"""
#-------------------------------------------------------------------------------------------------------------------------------------------------

def vars_rewrite():

    rsa_country=input(str("Country:"))
    rsa_province=input(str("Province:"))
    rsa_city=input(str("City:"))
    rsa_organization=input(str("Organization:"))
    rsa_email=input(str("email:"))
    rsa_ou=input(str("Organization Unit:"))

    up_country=rsa_country.upper()

    char_count_country=len(rsa_country)
    if char_count_country == 2:
        rsaVarsFile = "/etc/openvpn/easy-rsa/vars"

        # Text to append
        varsTextCounrty = f'set_var EASYRSA_REQ_COUNTRY	"{up_country}"\n'
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
                file.write("done")
            print(f"Text added to {rsaVarsFile}")
        except FileNotFoundError:
            print(f"Error: File '{rsaVarsFile}' does not exist.")
        except PermissionError:
            print(f"Error: Permission denied to write to '{rsaVarsFile}'.")
        except Exception as e:
            print(f"An error occurred: {e}")

#-------------------------------------------------------------------------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------------------------------------------------------------------------
def CA_build(CA_dir):
    CA_dir = '/etc/openvpn/easy-rsa'
    os.chdir(CA_dir)
    os.system('./easyrsa init-pki')
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
    os.chdir(CA_dir)
    os.system(f'./easyrsa gen-req {serverName} nopass')
    os.system(f'./easyrsa sign-req server {serverName}')
    os.system('./easyrsa gen-dh')

#-------------------------------------------------------------------------------------------------------------------------------------------------

def log_create():

    if os.path.isfile('/var/log/openvpn/status.log'):
        pass
    else:
        os.system('mkdir -p /var/log/openvpn/status.log')
        logFir = True

    if os.path.isfile('/var/log/openvpn/ovpn.log'):
        pass
    else:
        os.system('mkdir /var/log/openvpn/ovpn.log')
        logSec = True

    if logFir == True and logSec == True:
        print("Logs files were created successfully")
    else:
        print("Logs files are already created")

def openVpnConf():

    os.system("touch /etc/openvpn/server.conf")
    with open("/etc/openvpn/server.conf", "a") as file:
        file.write("mode server")
        file.write("keepalive 10 120")
        file.write("status /var/log/openvpn/status.log")
        file.write("log /var/log/openvpn/ovpn.log")
        #os.system("cp /usr/share/doc/openvpn/sample/sample-config-files/server.conf /etc/openvpn")

#-------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------     Vecicky        -----------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------------------------------------------------

if os.geteuid() == 0:

    run = True
    serverName = None
    CA_dir = '/etc/openvpn/easy-rsa'
    easyrsa_path = "/usr/share/easy-rsa/3/easyrsa"

    installation()
    check_easyrsa(easyrsa_path)
    check_openvpn()
    print("Both Easy-RSA and OpenVPN are installed and functioning correctly.")
    dir_struc()
  
    if os.path.isfile('/etc/openvpn/easy-rsa/vars'):
        with open('/etc/openvpn/easy-rsa/vars', 'r') as varsFile:
            content = varsFile.read()
            if 'done' in content:
                pass
            else:
                vars_rewrite()
                rsa_set_up()
    else:
        vars_rewrite()
        rsa_set_up()

    if os.path.exists("/etc/openvpn/easy-rsa/pki/ca.crt"): 
        pass
    else:   
        CA_build(CA_dir)
    
    while run == True:
        if serverName == None:
            serverName=input("Server Name:")
        else:
            run = False
    
    server_cert_gen(CA_dir, serverName)
    log_create()
    openVpnConf()

else:
    print("ERROR: You need sudo rights!")
    sys.exit(1)



