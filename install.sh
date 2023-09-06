#!/bin/bash
echo "Firstly Become a root user."
echo
echo "It work best in Kali Linux"
echo
sleep 2
apt update -y
apt install figlet -y
apt install lolcat -y
apt install wafw00f -y
apt install wpscan -y
apt install whatweb -y
go install github.com/003random/getJS@latest
cp /root/go/bin/getJS /usr/bin
go install github.com/hakluke/hakrawler@latest
cp /root/go/bin/hakrawler /usr/bin
go install github.com/tomnomnom/waybackurls@latest
cp /root/go/bin/waybackurls /usr/bin
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
cp /root/go/bin/subfinder /usr/bin
#apt install subfinder -y
go install github.com/tomnomnom/assetfinder@latest
cp /root/go/bin/assetfinder /usr/bin
#apt install assetfinder -y
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
cp /root/go/bin/httpx /usr/bin
go install github.com/projectdiscovery/katana/cmd/katana@latest
cp /root/go/bin/katana /usr/bin
apt install nikto -y
go install  github.com/tomnomnom/gf@latest
cp /root/go/bin/gf /usr/bin
mkdir -p /root/.gf
cd contributors/examples
cp * /root/.gf
cd ../../..
apt install gobuster -y
go install github.com/ffuf/ffuf/v2@latest
cp /root/go/bin/ffuf /usr/bin
go install -v github.com/LukaSikic/subzy@latest
cp /root/go/bin/subzy /usr/bin
go install -v github.com/owasp-amass/amass/v4/...@master
cp /root/go/bin/amass /usr/bin
#apt install amass -y
apt install theharvester -y
apt install sqlmap -y
go install github.com/lc/gau/v2/cmd/gau@latest
cp /root/go/bin/gau /usr/bin
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
cp /root/go/bin/shuffledns /usr/bin
go install -v github.com/webklex/wappalyzer@main
cp /root/go/bin/wappalyzer /usr/bin
apt install xsser -y
apt install joomscan -y
mkdir -p contributors/ssti
git clone https://github.com/vladko312/SSTImap.git contributors/ssti
declare -A tools
tools=(
    ["figlet"]="figlet"
    ["lolcat"]="lolcat"
    ["wafw00f"]="wafw00f"
    ["wpscan"]="wpscan"
    ["whatweb"]="whatweb"
    ["getJS"]="getJS"
    ["hakrawler"]="hakrawler"
    ["waybackurls"]="waybackurls"
    ["assetfinder"]="assetfinder"
    ["subfinder"]="subfinder"
    ["httpx"]="httpx"
    ["katana"]="katana"
    ["nikto"]="nikto"
    ["gf"]="gf"
    ["gobuster"]="gobuster"
    ["ffuf"]="ffuf"
    ["subzy"]="subzy"
    ["amass"]="amass"
    ["theharvester"]="theharvester"
    ["sqlmap"]="sqlmap"
    ["gau"]="gau"
    ["shuffledns"]="shuffledns"
    ["wappalyzer"]="wappalyzer"
    ["xsser"]="xsser"
    ["joomscan"]="joomscan"
    ["SSTImap"]="SSTImap"
)
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
for tool_name in "${!tools[@]}"; do
    package_name="${tools[$tool_name]}"
    if command -v "$tool_name" &>/dev/null; then
        echo -e "${GREEN}$tool_name is already installed.${NC}"
    else
        echo -e "${RED}$tool_name is not installed.${NC}"
    fi
done
echo -e "\n${RED}Please install the missing tools manually.${NC}"

