#! /usr/bin/env python3
import sys
import codecs
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import argparse
import requests
from requests import RequestException
from bs4 import BeautifulSoup as bsop
import sys
import re

urllib3.disable_warnings()

def banner():
    print("""                                                             
  ___ _             _  __     _____     _                       
 / __| |_  ___ _ __(_)/ _|_  |_   _|_ _| |_____ _____ _____ _ _ 
 \__ \ ' \/ _ \ '_ \ |  _| || || |/ _` | / / -_) _ \ V / -_) '_|
 |___/_||_\___/ .__/_|_|  \_, ||_|\__,_|_\_\___\___/\_/\___|_|  
              |_|         |__/                                  
    Just Another Shopify Subdomain Takeover Tool                                                        
    """)
class color:
   purple = '\033[95m'
   cyan = '\033[96m'
   darkcyan = '\033[36m'
   blue = '\033[94m'
   green = '\033[92m'
   yellow = '\033[93m'
   red = '\033[91m'
   bold = '\033[1m'
   orange = '\033[33m'
   underline = '\033[4m'
   reset = '\033[0m'
   magenta = "\033[35m"

parser = argparse.ArgumentParser()
parser.add_argument('-l', '--list', metavar='list.txt', type=str, help='File contain lists of domain')
parser.add_argument('-t', '--thread', metavar='5', nargs='?', default=5, type=int, help='Thread value. Default value is 5')
parser.add_argument('--vuln', default=False, action="store_true", help="Print only vuln domain")
args = parser.parse_args()
domainlist = args.list
worker = args.thread
vuln_only = args.vuln

def argscheck():
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    elif domainlist == None:
        parser.print_help(sys.stderr)
        print()
        print(f"{color.red}{color.bold}Error: Domain list is mandatory{color.reset}{color.reset}")
        sys.exit(1)
    elif domainlist != None:
        try:
            codecs.open(domainlist, encoding="utf-8", errors="strict").readlines()
        except Exception as err:
            print(f"{color.red}{color.bold}Error: {type(err).__name__} was raised. Please provide valid domain list{color.reset}{color.reset}")
            sys.exit(1)

def req_format(probed_domain):
    if not probed_domain.startswith("http://") and not probed_domain.startswith("https://"):
        probed_domain = 'http://' + probed_domain
    else:
        probed_domain = probed_domain
    return requests.get(probed_domain, allow_redirects=True, verify=False, timeout=7)
def shopify_take(probed_domain):
    try:
        domaincheck = req_format(probed_domain)
        if domaincheck.status_code == 404:           
            vuln_parse = bsop(domaincheck.text, "html.parser")
            vuln_check = vuln_parse.find_all(text="Sorry, this shop is currently unavailable.")
            if vuln_check:
                if vuln_only:
                    return probed_domain
                else:
                    return(f"[{color.bold}{color.green}vuln{color.reset}] {probed_domain}")
            else:
                if vuln_only:
                    pass
                else:
                    return(f"[{color.red}erro{color.reset}] {probed_domain}")
        else:
            if vuln_only:
                pass
            else:
                return(f"[{color.red}erro{color.reset}] {probed_domain}")
    except RequestException as err:
        if vuln_only:
            pass
        else:
            return(f"[{color.red}erro{color.reset}] {probed_domain} {color.bold}{color.red}{type(err).__name__}{color.reset}")
def shopify_tko():
        with ThreadPoolExecutor(max_workers=worker) as executor:
            with codecs.open(domainlist, encoding="utf-8", errors="strict") as tglist:
                domainname = tglist.read().splitlines()
                loopcheck = [executor.submit(shopify_take, probed) for probed in domainname]
                try:
                    vuln_counter = 0
                    for future in as_completed(loopcheck):
                        if not vuln_only:
                            if "vuln" and not "erro" in future.result():
                                vuln_counter += 1
                        if future.result():
                            print(future.result())
                            if vuln_only:
                                vuln_counter += 1
                        else:
                            pass
                    print(f"\nFound {color.bold}{vuln_counter}{color.reset} domain vulnerable to Shopify Subdomain Takeover.")
                except KeyboardInterrupt as err:
                    executor.shutdown(wait=False, cancel_futures=True)
                    print(f"\n{color.bold}Terminate program. Please wait for current task pool finished...{color.reset}")

if __name__ == '__main__':
    banner()
    argscheck()
    try:
        shopify_tko()
    except Exception as err:
        print(f"{type(err).__name__} was raised: {err}")