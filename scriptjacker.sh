#!/bin/bash
# Website: https://scriptjacker.in/
red="\e[31m"
blue="\e[34m"
cyan="\e[36m"
pink="\e[35m"
green="\e[32m"
end="\e[0m"
bold="\e[1m"
yellow="\e[33m"
white="\e[97m"
clear
cat << "EOF"
               ..:::::::::..
           ..:::aad8888888baa:::..
        .::::d:?88888888888?::8b::::.
      .:::d8888:?88888888??a888888b:::.
    .:::d8888888a8888888aa8888888888b:::.
   ::::dP::::::::88888888888::::::::Yb::::
  ::::dP:::::::::Y888888888P:::::::::Yb::::
 ::::d8:::::::::::Y8888888P:::::::::::8b::::
.::::88::::::::::::Y88888P::::::::::::88::::.
:::::Y8baaaaaaaaaa88P:T:Y88aaaaaaaaaad8P:::::
:::::::Y88888888888P::|::Y88888888888P:::::::
::::::::::::::::888:::|:::888::::::::::::::::
`:::::::::::::::8888888888888b::::::::::::::'
 :::::::::::::::88888888888888::::::::::::::
  :::::::::::::d88888888888888:::::::::::::
   ::::::::::::88::88::88:::88::::::::::::
    `::::::::::88::88::88:::88::::::::::'
      `::::::::88::88::P::::88::::::::'
        `::::::88::88:::::::88::::::'
           ``:::::::::::::::::::''
                ``:::::::::''

EOF
figlet -f slant "scriptjacker" | lolcat
echo
printf "${bold}${blue}v.1.0${end}${end}                                          ${bold}${pink}Parth Narula${end}${end} "
echo
function helpfunc(){
echo
echo
printf "${red}[+]${end} Argument: ./scriptjacker.sh ${pink}-h, --help${end}"
echo
echo
printf "${cyan}FLAGS:${end}"
echo
printf "${blue}[-]${end} ${red}-all${end} Do full recon process. ${green}(take more time than other tasks.)${end}"
echo
printf "${blue}[-]${end} ${red}-sub${end} Do indepth subdomain enumeration and task related to it."
echo
printf "${blue}[-]${end} ${red}-js${end} Do Javascript recon and find words from it."
echo
printf "${blue}[-]${end} ${red}-dns${end} Do indepth DNS enumeration information related."
echo
printf "${blue}[-]${end} ${red}-vp${end}  It take parameters/urls file and grep potentially vul param."
echo
echo
printf "${cyan}EXAMPLES:${end}"
echo
printf "${blue}[+]${end} Argument: ./scriptjacker.sh ${pink}-all${end} target.com"
echo
printf "${blue}[+]${end} Argument: ./scriptjacker.sh ${pink}-sub${end} target.com"
echo
printf "${blue}[+]${end} Argument: ./scriptjacker.sh ${pink}-vp${end} file.txt (Can enter full path like ../file.txt)"
echo
printf "${blue}[+]${end} Argument: ./scriptjacker.sh ${pink}-js${end} target.com"
}
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
helpfunc
elif [ "$1" = "-all" ]; then
clear
figlet -f slant "scriptjacker" | lolcat
printf "${bold}${blue}v.1.0${end}${end}                                          ${bold}${pink}Parth Narula${end}${end}"
echo
echo
printf " ${yellow}scriptjacker>${end}${green} More Targets - More Options - More Opportunities${end}" | pv -qL 30
sleep 0.4
echo
echo
printf " ${bold}${cyan}Host ${end}${end}${bold}${white}Discovery!${end}${end}"
echo
word=$(ping -c 1 "$2" 2> /dev/null | wc -w )
if [ "$word" -eq 0 ]; then
printf " ${pink}$2 ${end}host is ${bold}${red}down or unreachable.${end}${end}"
exit
else
tl=$(ping -c 1 "$2" | grep -o "ttl=[0-9]*" | tee ttl.txt)
ttl=$(cut -d= -f2 ttl.txt)
rm ttl.txt
if [ "$ttl" -gt 0 ] && [ "$ttl" -lt 65 ]; then
os="${bold}${yellow}Linux/Unix${end}${end}"
elif [ "$ttl" -gt 64 ] && [ "$ttl" -lt 129 ]; then
os="${bold}${yellow}Windows${end}${end}"
else
os="${bold}${yellow}Unknown${end}${end}"
fi
printf " ${pink}$2${end} is ${bold}${green}up.${end}${end} OS is $os"
dir=$(date +%Y-%m-%d)
mkdir -p "$2-$dir"
fi
echo
echo
echo
printf " ${bold}${cyan}Firewall ${end}${end}${bold}${white}Check!${end}${end}"
wafw00f "$2" 2> /dev/null 
echo
echo
printf " ${bold}${cyan}CMS ${end}${end}${bold}${white}Detection!${end}${end}"
echo
scan=$(whatweb "$2" | grep -o -E -i "squarespace|shopify|hubspot|contentful|concrete5|magento|wordpress|joomla|drupal|prestashop|moodle|weebly|wix" > scan.txt)
scan2=$(cat scan.txt | uniq -i > scan1.txt; rm scan.txt; cat scan1.txt)
case $scan2 in 
wordpress|WordPress|Wordpress) printf " ${green}$2${end} Running Wordpress."
echo
read -p " Do you want to run Wpscan (Take more time.) [y|n]--# " wptool
case "$wptool" in
y|Y|yes) printf "${bold}${red} [+] ${end}${end}${bold}${green}Running Wpscan${end}${end}"
echo
wpscan --url "$2" --random-user-agent -e vt,vp,u,dbe >> "wpscan.txt"
 mv wpscan.txt "$2-$dir"/
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Not running Wpscan${end}${end}"
;;
*) printf "${red} Try again later.${end}"
esac
;;
joomla|Joomla) printf " ${green}$2${end} Running Joomla." 
echo
read -p " Do you want to run Joomscan (Take more time.) [y|n]--# " jtool
case "$jtool" in
y|Y|yes) printf "${bold}${red} [+] ${end}${end}${bold}${green}Running Joomscan${end}${end}"
echo
#perl contributors/joomscan/joomscan.pl -u "$2" -r -nr | tee -a "joomscan.txt"
joomscan -u "$2" -r -nr | tee -a "joomscan.txt"
mv joomscan.txt "$2-$dir"/
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Not running Joomscan${end}${end}"
;;
*) printf "${red} Try again later.${end}"
esac
;;
drupal|Drupal) printf " ${green}$2${end} Running Drupal."
;;
Magento|magento) printf " ${green}$2${end} Running Magento."
;;
prestashop|PrestaShop|Prestashop) printf " ${green}$2${end} Running Prestashop."
;;
Concrete5|concrete5) printf " ${green}$2${end} Running Concrete5"
;;
contentful|Contentful|ContentFul) printf " ${green}$2${end} Running Contentful."
;;
sitefinity|Sitefinity|SiteFinity) printf " ${green}$2${end} Running Sitefinity."
;;
moodle|Moodle) printf " ${green}$2${end} Running Moodle."
;;
weebly|Weebly) printf " ${green}$2${end} Running Weebly."
;;
wix|Wix) printf " ${green}$2${end} Running Wix."
;;
hubspot|Hubspot|HubSpot) printf " ${green}$2${end} Running Hubspot."
;;
shopify|Shopify|ShopiFy) printf " ${green}$2${end} Running Shopify."
echo
read -p " Do you want to run ShopifyTakeover (Take more time.) [y|n]--# " shoptool
case "$shoptool" in
y|Y|yes) printf "${bold}${red} [+] ${end}${end}${bold}${green}Running ShopifyTakeover${end}${end}"
echo
pip install -r contributors/requirements2.txt
echo "$2" > contributors/domain.txt
python3 contributors/ShopifyTakeover.py -l domain.txt | tee -a "shopifytakeover.txt"
rm contributors/domain.txt
mv shopifytakeover.txt "$2-$dir"/
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Not running ShopifyTakeover${end}${end}"
;;
*) printf "${red} Try again later.${end}"
esac
;;
squarespace|SquareSpace|Squarespace) printf " ${green}$2${end} Running Squarespace."
;;
*) printf " ${green}$2${end} No CMS Detected."
;;
esac
rm scan1.txt
echo
echo
echo
printf " ${bold}${cyan}DNS ${end}${end}${bold}${white}Recon!${end}${end}"
echo
dig "$2" NS +nocomments +noall +answer > "$2-$dir"/dns_info.txt
dig "$2" MX +nocomments +noall +answer >> "$2-$dir"/dns_info.txt
dig "$2" A +nocomments +noall +answer >> "$2-$dir"/dns_info.txt
dig "$2" CNAME +nocomments +noall +answer >> "$2-$dir"/dns_info.txt
dig "$2" SOA +nocomments +noall +answer >> "$2-$dir"/dns_info.txt
dig "$2" TXT +nocomments +noall +answer >> "$2-$dir"/dns_info.txt
#pip install -r contributors/dnsdumpster/requirements.txt 1> /dev/null 2> /dev/null
#python3 contributors/dnsdumpster/dnsdumpster.py -d "$2" 2> /dev/null >> "$2-$dir"/dns_info.txt
printf " ${cyan}Reference: ${end}https://dnsdumpster.com/"
echo
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Basic ${end}${end}${bold}${white}Info Gathering!${end}${end}"
echo
whois "$2" > "basicinfo.txt"
whatweb -v -a 3 "https://$2" >> "basicinfo.txt"
mv basicinfo.txt "$2-$dir"/
theHarvester -d "$2" -l 150 -b all >> "$2-$dir/basicinfo.txt" 2> /dev/null
wappalyzer -target "https://$2" >> "$2-$dir/basicinfo.txt"
echo " Use Wappalyzer extention and Buildwith website manually."
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Google ${end}${end}${bold}${white}Dorking!${end}${end}"
echo
bash contributors/fgds.sh "$2" 2> /dev/null > "google_dorks.txt"
mv google_dorks.txt "$2-$dir"/
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Github ${end}${end}${bold}${white}Dorking!${end}${end}" #dork change
echo
echo " Do you want to automate Github Dorking"
read -p " (It require GitHub Personal Access Token) [y|n]--# " gitdork
case "$gitdork" in
y|Y|yes) echo
read -p " Enter your github access token (type q to exit git dork.)--# " accesstoken
if [ "$accesstoken" = "q" ] || [ "$accesstoken" = "Q" ]; then
printf "${bold}${red} [-] ${end}${end}${bold}${green}Ok. Exiting${end}${end}"
echo
else
printf "${bold}${red} [+] ${end}${end}${bold}${green}Running GitDorker${end}${end}"
echo
pip3 install -r contributors/requirements.txt 1> /dev/null 2> /dev/null
python3 contributors/GitDorker.py -t "$accesstoken" -q "$2" -d contributors/Dorks/medium_dorks.txt > "github_dorks.txt"
mv github_dorks.txt "$2-$dir"/
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
fi
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Ok. Do manually${end}${end}"
;;
*) printf "${red} Try again later.${end}"
esac
echo
echo
echo
printf " ${bold}${cyan}Javascript ${end}${end}${bold}${white}Recon!${end}${end}"
echo
getJS --url https://"$2" --complete > "js.txt"
echo "https://$2/" | hakrawler -u | grep -E '\.js$' >> "js.txt"
waybackurls "$2" | grep -E '\.js$' >> "js.txt"
cat js.txt | sort | uniq > js_recon.txt
rm js.txt
cat js_recon.txt | python3 contributors/getjswords.py > js_words.txt
mv js_words.txt "$2-$dir"/
wordcount=$(wc -l js_recon.txt | grep -o '[0-9]\+')
if [ "$wordcount" -gt 2200 ]; then
:
else
printf " ${blue}[~]${end}--# You find ${bold}${red}$wordcount${end}${end} ${bold}${green}javascript files.${end}${end}"
echo
read -p " Do you wanna grep active javascript files (Takes some Time.) [y|n]--# " jsrecon
case "$jsrecon" in
y|Y|yes) printf "${bold}${red} [+] ${end}${end}${bold}${green}Finding Active JS Files.${end}${end}"
echo
cat js_recon.txt | httpx -mc 200,301,301 -silent > "$2-$dir"/active_js.txt
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Ok. Do manually${end}${end}"
echo
;;
*) printf "${red} Try again later.${end}"
echo
esac
fi
mv js_recon.txt "$2-$dir"/
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Subdomain ${end}${end}${bold}${white}Enumeration!${end}${end}"
echo
subfinder -d "$2" -silent > "sub.txt"
shuffledns -d "$2" -r contributors/resolvers.txt -w contributors/subdomain.txt -silent >> "sub.txt"
bash contributors/crt.sh -d "$2" >> "sub.txt"
assetfinder  -subs-only "$2" >> "sub.txt"
amass enum -passive -d "$2" -silent >> "sub.txt"
cat sub.txt | sort | uniq > subdomains.txt
rm sub.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Active ${end}${end}${bold}${white}Subdomains!${end}${end}"
echo
cat subdomains.txt | httpx -mc 200 -silent > active.txt
cat subdomains.txt | httpx -mc 404 -silent > "$2-$dir"/takeover.txt
cat subdomains.txt | httpx -mc 301,301 -silent -follow-redirects > "$2-$dir"/redirection_sub.txt
wordcount=$(wc -l active.txt | grep -o '[0-9]\+')
if [ "$wordcount" -gt 1200 ]; then
:
else
printf " ${blue}[~]${end}--# You find ${bold}${red}$wordcount${end}${end} ${bold}${green}active subdomains.${end}${end}"
cat active.txt | httpx -sc -follow-redirects -tech-detect -silent -server -cname -ip -websocket -probe -asn -cdn > "$2-$dir"/httpx.txt
fi
mv subdomains.txt "$2-$dir"/
mv active.txt "$2-$dir"/
echo
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Network ${end}${end}${bold}${white}Scanning!${end}${end}"
echo
printf "${yellow}+---------------------------------------+${end}"
echo
printf "${yellow}|${end} ${green}1 Want to run scan on target.com only.${end}${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}2 Want to run scan on all subdomains.${end} ${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}3 Don't wanna run Nmap scan.${end}          ${yellow}|${yellow}"
echo
printf "${yellow}+---------------------------------------+${end}"
echo
read -p " Enter the scan type--# " nmapscan
case "$nmapscan" in
1) printf "${bold}${red} [+] ${end}${end}${bold}${green}Running Nmap on $2${end}${end}"
echo
nmap -sV -O "$2" -p- --script vuln > "$2-$dir"/nmap.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
;;
2) printf "${bold}${red} [+] ${end}${end}${bold}${green}Running Nmap on subdomains.${end}${end}"
echo
grep -oE '(https?://)?([^/]+)' "$2-$dir"/active.txt | sed -E 's/https?:\/\///' > scan.txt
nmap -iL scan.txt -A > "$2-$dir"/nmap.txt
rm scan.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
;;
3) printf "${bold}${red} [-] ${end}${end}${bold}${green}Ok. Do manually${end}${end}"
;;
*) printf "${red} Try again later.${end}"
esac
echo
echo
echo
printf " ${bold}${cyan}Subdomain ${end}${end}${bold}${white}Takeover!${end}${end}"
echo
pip install -r contributors/requirements1.txt 1> /dev/null 2> /dev/null
python3 contributors/sub404.py -f "$2-$dir"/takeover.txt -p https > "$2-$dir"/sub_takeover.txt
subzy run --targets "$2-$dir"/takeover.txt >> "$2-$dir"/sub_takeover.txt 
rm "$2-$dir"/takeover.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Directory ${end}${end}${bold}${white}Busting!${end}${end}"
echo
printf " Press ${red}ctrl+c${end} to stop the dir busting tool."
echo
gobuster dir -u "https://$2/" -w contributors/common.txt -q --random-agent | tee "$2-$dir"/directory.txt
ffuf -u https://$2/FUZZ -w contributors/directory-list-2.3-small.txt -mc 200 -c -v >> "$2-$dir"/directory.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Grabing ${end}${end}${bold}${white}Endpoints and Parameters!${end}${end}"
echo
katana -list "$2-$dir"/active.txt > "$2-$dir"/crawlin.txt
gau "$2" >> "$2-$dir"/crawlin.txt
sort "$2-$dir"/crawlin.txt | uniq > "$2-$dir"/crawling.txt
rm "$2-$dir"/crawlin.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Vulnerable ${end}${end}${bold}${white}Endpoints and Parameters!${end}${end}"
echo
mkdir "$2-$dir"/vul_param
gf xss "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/xss.txt
gf urls "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/urls.txt
gf upload-fields "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/file_upload.txt
gf takeovers "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/sub_takeover.txt
gf strings "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/strings.txt
gf ssti "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/ssti.txt
gf ssrf "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/ssrf.txt
gf sqli "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/sqli.txt
gf servers "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/servers.txt
gf sec "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/sec.txt
gf s3-buckets "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/s3-buckets.txt
gf redirect "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/redirect.txt
gf rce "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/rce.txt
gf php-sources "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/php.txt
gf lfi "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/lfi.txt
gf ip "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/ip.txt
gf json-sec "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/json.txt
gf aws-keys "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/aws.txt
gf base64 "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/base64.txt
gf cors "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/cors.txt
gf firebase "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/firebase.txt
gf http-auth "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/http.txt
gf idor "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/idor.txt
gf img-traversal "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/img.txt
gf interestingparams "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/params.txt
gf interestingsubs "$2-$dir"/crawling.txt > "$2-$dir"/vul_param/subs.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Testing ${end}${end}${bold}${white}403 Bypass!${end}${end}"
echo
printf " ${green}Directory Busting Output${end}"
cat "$2-$dir"/directory.txt | grep -i "Status: 403"
echo
printf " ${white}Example:${white} ${red}cgi-bin${end}"
echo
read -p " SET directory to do bypass test (without /): " byp
bash contributors/403bypass.sh "https://$2" "$byp" > "$2-$dir"/403_byp.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf "${pink}(^_^)${end} ${bold}${yellow}Recon is completed.${end}${end} ${green}Wana move to some vulnerability finding.${end}"
echo
printf "${yellow}+-----------------------------------+${end}"
echo
printf "${yellow}|${end} ${green}1 Run nuclei, nikto and rapidscan.${end}${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}2 Run SQLMAP for SQLI.${end}            ${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}3 Run xsser for XSS testing.${end}      ${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}4 Run SSTImap for SSTI.${end}           ${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}5 Run lazys3 for open bucket.${end}     ${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}6 Run all things.${end}                 ${yellow}|${end}"
echo
printf "${yellow}|${end} ${green}7 exit.${end}                           ${yellow}|${end}"
echo
printf "${yellow}+-----------------------------------+${end}"
echo
read -p " Enter option--# " forward
case "$forward" in
1) echo
printf " ${bold}${cyan}Vulnerability ${end}${end}${bold}${white}Scanning!${end}${end}"
echo
nuclei -ut 1> /dev/null 2> /dev/null
nuclei -l "$2-$dir"/active.txt | tee "$2-$dir"/vul_scan.txt
echo
echo " Do you wanna run rapidscan" 
read -p " (It will clear all terminal output till now.) [y|n]--# " rapid
case "$rapid" in
y|Y|yes) printf "${bold}${red} [+] ${end}${end}${bold}${green}Running rapidscan.${end}${end}"
echo
python3 contributors/setup.py install 1> /dev/null 2> /dev/null
python3 contributors/rapidscan.py "$2"
echo
echo "Your output is saved in contributors/rapid/ directory."
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Ok. Do manually${end}${end}"
;;
*) printf "${red} Try again later.${end}"
esac
echo
echo
nikto -host "https://$2" | tee -a "$2-$dir"/vul_scan.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
 printf " Thanks for using ${green}@scriptjacker.in${green}"
;;
2) echo
printf " ${bold}${cyan}Testing ${end}${end}${bold}${white}SQLI!${end}${end}"
echo
sqlmap -m "$2-$dir"/vul_param/sqli.txt --random-agent --batch | tee "$2-$dir"/sqlmap.txt
sqlmap -u "https://$2" --batch --random-agent --crawl=2 | tee -a "$2-$dir"/sqlmap.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
 printf " Thanks for using ${green}@scriptjacker.in${green}"
;;
3) echo
printf " ${bold}${cyan}Testing ${end}${end}${bold}${white}XSS!${end}${end}"
echo
cd contributors
python3 xsser -u "http://$2" --Cl --Cw 3 -c 100 > ../"$2-$dir"/xsser.txt
python3 xsser -i "$2-$dir"/vul_param/xss.txt  -c 100 --Cl --Cw 3 >> ../"$2-$dir"/xsser.txt
cd ../
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
 printf " Thanks for using ${green}@scriptjacker.in${green}" 
;;
4) echo
printf " ${bold}${cyan}Testing ${end}${end}${bold}${white}SSTI!${end}${end}"
echo
python3 contributors/ssti/sstimap.py -u "https://$2" -c 2 -A > "$2-$dir"/ssti.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
 printf " Thanks for using ${green}@scriptjacker.in${green}"
;;
5) echo
printf " ${bold}${cyan}Finding ${end}${end}${bold}${white}Open Buckets!${end}${end}"
echo
cd contributors/
ruby lazys3.rb "$2" | tee ../"$2-$dir"/buckets.txt
cd ../
echo
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
 printf " Thanks for using ${green}@scriptjacker.in${green}"
;;
6) echo
printf " ${bold}${cyan}Vulnerability ${end}${end}${bold}${white}Scanning!${end}${end}"
echo
nuclei -ut 1> /dev/null 2> /dev/null
nuclei -l "$2-$dir"/active.txt | tee "$2-$dir"/vul_scan.txt
echo
echo " Do you wanna run rapidscan" 
read -p " (It will clear all terminal output till now.) [y|n]--# " rapid
case "$rapid" in
y|Y|yes) printf "${bold}${red} [+] ${end}${end}${bold}${green}Running rapidscan.${end}${end}"
echo
python3 contributors/setup.py install 1> /dev/null 2> /dev/null
python3 contributors/rapidscan.py "$2"
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Ok. Do manually${end}${end}"
;;
*) printf "${red} Try again later.${end}"
esac
echo
echo
nikto -host "https://$2" | tee -a "$2-$dir"/vul_scan.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Testing ${end}${end}${bold}${white}SQLI!${end}${end}"
echo
sqlmap -m "$2-$dir"/vul_param/sqli.txt --random-agent --batch | tee "$2-$dir"/sqlmap.txt
sqlmap -u "https://$2" --batch --random-agent --crawl=2 | tee -a "$2-$dir"/sqlmap.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Testing ${end}${end}${bold}${white}XSS!${end}${end}"
echo
cd contributors/
python3 xsser -u "http://$2" --Cl --Cw 3 -c 100 > ../"$2-$dir"/xsser.txt
python3 xsser -i "../$2-$dir"/vul_param/xss.txt -c 100 --Cl --Cw 3 >> ../"$2-$dir"/xsser.txt
cd ../
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Testing ${end}${end}${bold}${white}SSTI!${end}${end}"
echo
python3 contributors/ssti/sstimap.py -u "https://$2" -c 2 -A > "$2-$dir"/ssti.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
echo
printf " ${bold}${cyan}Finding ${end}${end}${bold}${white}Open Buckets!${end}${end}"
echo
cd contributors/
ruby lazys3.rb "$2" | tee ../"$2-$dir"/buckets.txt
cd ../
echo
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
 printf " Thanks for using ${green}@scriptjacker.in${green}"
;;
7) echo
 printf " Thanks for using ${green}@scriptjacker.in${green}"
exit
;;
*) "${red} Try again later.${end}"
echo
esac
elif [ "$1" = "-sub" ]; then
echo
printf " ${bold}${cyan}Performing ${end}${end}${bold}${white}Indepth Subdomain Enumeration!${end}${end}"
echo
word=$(ping -c 1 "$2" 2> /dev/null | wc -w )
if [ "$word" -eq 0 ]; then
printf " ${pink}$2 ${end}host is ${bold}${red}down or unreachable.${end}${end}"
exit
else
tl=$(ping -c 1 "$2" | grep -o "ttl=[0-9]*" | tee ttl.txt)
ttl=$(cut -d= -f2 ttl.txt)
rm ttl.txt
fi
if [ "$ttl" -gt 0 ] && [ "$ttl" -lt 65 ]; then
os="${bold}${yellow}Linux/Unix${end}${end}"
elif [ "$ttl" -gt 64 ] && [ "$ttl" -lt 129 ]; then
os="${bold}${yellow}Windows${end}${end}"
else
os="${bold}${yellow}Unknown${end}${end}"
fi
printf " ${pink}$2${end} is ${bold}${green}up.${end}${end} OS is $os"
dir=$(date +%Y-%m-%d)
mkdir -p "$2-$dir-sub-enum"
echo
subfinder -d "$2" -silent > "sub.txt"
shuffledns -d "$2" -r contributors/resolvers.txt -w contributors/subdomain.txt -silent >> "sub.txt"
bash contributors/crt.sh -d "$2" >> "sub.txt"
assetfinder  -subs-only "$2" >> "sub.txt"
amass enum -passive -d "$2" -silent >> "sub.txt"
cat sub.txt | sort | uniq > subdomains.txt
rm sub.txt
wordcount=$(wc -l subdomains.txt | grep -o '[0-9]\+')
if [ "$wordcount" -eq 0 ]; then
:
else
printf " ${blue}[~]${end}--# You find ${bold}${red}$wordcount${end}${end} ${bold}${green}subdomains.${end}${end}"
fi
mv subdomains.txt "$2-$dir-sub-enum"/
echo
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
elif [ "$1" = "-js" ]; then
echo
printf " ${bold}${cyan}Performing ${end}${end}${bold}${white}Javascript Recon!${end}${end}"
dir=$(date +%Y-%m-%d)
mkdir -p "$2-$dir-js-enum"
getJS --url https://"$2" --complete > "js.txt"
echo "https://$2/" | hakrawler -u | grep -E '\.js$' >> "js.txt"
waybackurls "$2" | grep -E '\.js$' >> "js.txt"
cat js.txt | sort | uniq > js_recon.txt
rm js.txt
cat js_recon.txt | python3 contributors/getjswords.py > js_words.txt
mv js_words.txt "$2-$dir-js-enum"
wordcount=$(wc -l js_recon.txt | grep -o '[0-9]\+')
if [ "$wordcount" -gt 2200 ]; then
:
else
echo
printf " ${blue}[~]${end}--# You find ${bold}${red}$wordcount${end}${end} ${bold}${green}javascript files.${end}${end}"
echo
read -p " Do you wanna grep active javascript files (Takes some Time.) [y|n]--# " jsrecon
case "$jsrecon" in
y|Y|yes) printf "${bold}${red} [+] ${end}${end}${bold}${green}Finding Active JS Files.${end}${end}"
echo
cat js_recon.txt | httpx -mc 200,301,301 -silent > "$2-$dir-js-enum"/active_js.txt
;;
N|n|no) printf "${bold}${red} [-] ${end}${end}${bold}${green}Ok. Do manually${end}${end}"
echo
;;
*) printf "${red} Try again later.${end}"
echo
esac
fi
mv js_recon.txt "$2-$dir-js-enum"/
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
elif [ "$1" = "-dns" ]; then
echo
printf " ${bold}${cyan}Performing ${end}${end}${bold}${white}Indepth DNS Enumeration!${end}${end}"
echo
word=$(ping -c 1 "$2" 2> /dev/null | wc -w )
if [ "$word" -eq 0 ]; then
printf " ${pink}$2 ${end}host is ${bold}${red}down or unreachable.${end}${end}"
exit
else
tl=$(ping -c 1 "$2" | grep -o "ttl=[0-9]*" | tee ttl.txt)
ttl=$(cut -d= -f2 ttl.txt)
rm ttl.txt
fi
if [ "$ttl" -gt 0 ] && [ "$ttl" -lt 65 ]; then
os="${bold}${yellow}Linux/Unix${end}${end}"
elif [ "$ttl" -gt 64 ] && [ "$ttl" -lt 129 ]; then
os="${bold}${yellow}Windows${end}${end}"
else
os="${bold}${yellow}Unknown${end}${end}"
fi
printf " ${pink}$2${end} is ${bold}${green}up.${end}${end} OS is $os"
echo
dir=$(date +%Y-%m-%d)
mkdir -p "$2-$dir-dns-enum"
echo
dig "$2" > "$2-$dir-dns-enum"/dns_info.txt
echo
pip install -r contributors/dnsdumpster/requirements.txt 1> /dev/null 2> /dev/null
python3 contributors/dnsdumpster/dnsdumpster.py -d "$2" 2> /dev/null >> "$2-$dir-dns-enum"/dns_info.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
elif [ "$1" = "-vp" ]; then
echo
printf " ${bold}${cyan}Grabing ${end}${end}${bold}${white}Vulnerable Parameters.!${end}${end}"
echo
dir=$(date +%Y-%m-%d)
mkdir -p "$dir-vul-param"
gf xss "$2" > "$dir-vul-param"/xss.txt
gf urls "$2" > "$dir-vul-param"/urls.txt
gf upload-fields "$2" > "$dir-vul-param"/file_upload.txt
gf takeovers "$2" > "$dir-vul-param"/sub_takeover.txt
gf strings "$2" > "$dir-vul-param"/strings.txt
gf ssti "$2" > "$dir-vul-param"/ssti.txt
gf ssrf "$2" > "$dir-vul-param"/ssrf.txt
gf sqli "$2" > "$dir-vul-param"/sqli.txt
gf servers "$2" > "$dir-vul-param"/servers.txt
gf sec "$2" > "$dir-vul-param"/sec.txt
gf s3-buckets "$2" > "$dir-vul-param"/s3-buckets.txt
gf redirect "$2" > "$dir-vul-param"/redirect.txt
gf rce "$2" > "$dir-vul-param"/rce.txt
gf php-sources "$2" > "$dir-vul-param"/php.txt
gf lfi "$2" > "$dir-vul-param"/lfi.txt
gf ip "$2" > "$dir-vul-param"/ip.txt
gf json-sec "$2" > "$dir-vul-param"/json.txt
gf aws-keys "$2" > "$dir-vul-param"/aws.txt
gf base64 "$2" > "$dir-vul-param"/base64.txt
gf cors "$2" > "$dir-vul-param"/cors.txt
gf firebase "$2" > "$dir-vul-param"/firebase.txt
gf http-auth "$2" > "$dir-vul-param"/http.txt
gf idor "$2" > "$dir-vul-param"/idor.txt
gf img-traversal "$2" > "$dir-vul-param"/img.txt
gf interestingparams "$2" > "$dir-vul-param"/params.txt
gf interestingsubs "$2" > "$dir-vul-param"/subs.txt
printf " ${bold}${yellow}[RUNNING]${end}${end}"
printf "${green}#######################################${end} ${bold}${red}Done.${end}${end}" | pv -qL 35
echo
echo
else
echo
printf "${red}[+]${end} Argument: ./scriptjacker.sh ${pink}-h, --help${end}"
echo
echo
printf "${green}Invalid flag: ${end}${red}$1${end}"
fi
