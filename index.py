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




installation()


