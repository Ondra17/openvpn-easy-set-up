
import subprocess

def installation():
    subprocess.run(["dnf", "update", "-y"])
    subprocess.run(["dnf", "install", "-y", "epel-release"])
    subprocess.run(["dnf", "install", "-y", "openvpn", "easy-rsa"])

    result = subprocess.run(["openvpn", "--version"], capture_output=True, text=True)
    if result.returncode == 0:
        print("################################################")
        print("#                                              #")
        print("# OpenVPN and Easy-RSA installed successfully! #")
        print("#                                              #")
        print("################################################")
        print(result.stdout)
    else:
        print("OpenVPN installation failed.")
        print(result.stderr)


def dir_struc():
    subprocess.run(["mkdir", "-p", "/etc/openvpn/easy-rsa/keys"])

def rsa_set_up():
    subprocess.run(["cp", "-ai", "/usr/share/easy-rsa/3/*", "/etc/openvpn/easy-rsa"])

installation()
dir_struc()
rsa_set_up()
