#!/usr/bin/env bash 

#this tells the os to run this file using bash. we can use ./install.sh on it
#it needs to be on the first line

#stops the script if any command fails.
set -e

echo "====== Talos Installer ======"

#refresh apt package index before installing anything
#some cloud images couldnt install pip without this
echo "[+] Refreshing apt package index..."
sudo apt-get update -qq


#apt packages installation: qemu-utils, parted
for pkg in qemu-utils parted; do

    #run command discard output (void). if command runs= true so pkg already installed
    #same logic for the rest 
    if dpkg -s "$pkg" &> /dev/null; then
        echo "[!] Skipping package $pkg (already installed)"
    else
        echo "[+] Installing $pkg..."
        sudo apt-get install -y "$pkg"
    fi
done
#pip3 installation (fresh systems need it)
if command -v pip3 &> /dev/null; then
    echo "[+] Skipping pip3 installation (already installed)"
else
    echo "[+] Installing pip3..."
    sudo apt-get install -y python3-pip
fi


#pip packages installation: tabulate,openpyxl,boto3 etc
for pkg in tabulate openpyxl boto3 paramiko google-cloud-storage google-cloud-compute; do
    if pip3 show "$pkg" &> /dev/null; then
        echo "[!] Skipping Package $pkg (already installed)"
    else
        echo "[+] Installing package $pkg..."
        if ! sudo pip3 install "$pkg" --break-system-packages --ignore-installed; then
            echo "[-] --break-system-packages attempt failed for $pkg, trying without flag..."
            sudo pip3 install --ignore-installed"$pkg"
        fi
    fi
done

#force a modern pyOpenSSL regardless of any apt-installed version, old version conflicts with boto3
echo "[+] Installing/upgrading pyOpenSSL..."
sudo pip3 install pyOpenSSL --break-system-packages --ignore-installed --upgrade

#installation of scanners (syft,trivy,grype,osv-scanner)
#if command -v "scanner" exists= scanner already installed
if command -v syft &> /dev/null; then
    echo "[!] Skipping syft installation (already installed)"
else
    echo "[+] Installing syft..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo bash -s -- -b /usr/local/bin
fi



if command -v trivy &> /dev/null; then
    echo "[!] Skipping trivy installation (already installed)"
else
    echo "[+] Installing trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
fi


if command -v grype &> /dev/null; then
    echo "[!] Skipping grype installation (already installed)"
else
    echo "[+] Installing grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
fi 


if command -v osv-scanner &> /dev/null; then
    echo "[!] Skipping osv-scanner installation (already installed)"
else
    echo "[+] Installing osv-scanner..."
    wget -q https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -O /tmp/osv-scanner
    chmod +x /tmp/osv-scanner
    sudo mv /tmp/osv-scanner /usr/local/bin/osv-scanner
fi


###talos installation

#finding the folder the install script is located and cd into it
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#find talos path
TALOS_PATH="$SCRIPT_DIR/talos.py"

#make talos executable
chmod +x "$TALOS_PATH"

#make a symlink pointer so talos path always points to talos.py
#we now can call "talos" as a command
sudo ln -sf "$TALOS_PATH" /usr/local/bin/talos

echo "====== Talos installation completed sucsessfully ======"
