#!/bin/python
#      ___________      _______   ____  ____  ___
#     / ____/__  /     / ____/ | / / / / /  |/  /
#    / __/    / /     / __/ /  |/ / / / / /|_/ / 
#   / /___   / /__   / /___/ /|  / /_/ / /  / /  
#  /_____/  /____/  /_____/_/ |_/\____/_/  /_/   
#                                              
#  Because the script kiddies are the real hackers ;)
#
#
# Description: This script just uses find to locate all executable files on the system
#              with their suid bit set who are (by default) owned by root. It then
#              parses this output looking for any programs that have a know priv esc
#              (or at least one published on GTFOBins: https://gtfobins.github.io)
#              if it finds such a program it performs the exploit and runs a whoami
#              to verify that it was successful and if so drops out to a shell.

#----------
# Libraries
# ---------

import os, sys

from termcolor import colored

import sublist3r
import socket
import re

#----------
# Constants
#----------

url_regex = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"

#---------------
# Vanity Banners
#---------------

buff='                     ___________      _______   ____  ____  ___\n'
buff+='                    / ____/__  /     / ____/ | / / / / /  |/  /\n'
buff+='                   / __/    / /     / __/ /  |/ / / / / /|_/ / \n'
buff+='                  / /___   / /__   / /___/ /|  / /_/ / /  / /  \n'
buff+='                 /_____/  /____/  /_____/_/ |_/\\____/_/  /_/   \n'
buff+='                                                               \n'

print(colored(buff, 'magenta'));

buff='               ,-\\__\n'
buff+='                |f-"Y\\   _____________________\n'
buff+='                \\()7L/  |     Be Queer!       |\n'
buff+='                 cgD    |     Do H4Ck5!       |  __ _\n'
buff+="                 |\\(     --------------------- .'  Y '>,\n"
buff+='                  \\ \\                \\       / _   _   \\\n'
buff+='                   \\\\\\                \\      )(_) (_)(|}\n'
buff+='                    \\\\\\                      {  4A   } /\n'
buff+='                     \\\\\\                      \\uLuJJ/\\l\n'
buff+='                      \\\\\\                     |3    p)/\n'
buff+='                       \\\\\\___ __________      /nnm_n//\n'
buff+='                       c7___-__,__-)\\,__)(".  \\_>-<_/D\n'
buff+='                                  //V     \\_"-._.__G G_c__.-__<"/ ( \\\n'
buff+='                                         <"-._>__-,G_.___)\\   \\7\\\n'
buff+='                                        ("-.__.| \\"<.__.-" )   \\ \\\n'
buff+='                                        |"-.__"\\  |"-.__.-".\\   \\ \\\n'
buff+='                                        ("-.__"". \\"-.__.-".|    \\_\\\n'
buff+='                                        \\"-.__""|!|"-.__.-".)     \\ \\\n'
buff+='                                         "-.__""\\_|"-.__.-"./      \\ l\n'
buff+='                                          ".__""">G>-.__.-">       .--,_\n'
buff+='                                              ""  G\n'
buff+='\n'

print(colored(buff, 'cyan'))

print(colored("                 Because the script kiddies are the real hackers ;)\n\n", "green"))

#----------
# Functions
#----------

def get_subdomains(brute):

    """ This function exists for the sole purpose of parsing the bat-shit crazy output that
        the psychopathic developers of sublist3r decided that their library should return
        to their users. Seriously, nice script, but fuck those guys """
    
    # scrape the web for domains and get a crazy custom object back, type cast to a list of dictionaries

    raw = list(sublist3r.main(domain, threads=40, savefile=None, silent=True, verbose=False, enable_bruteforce=brute, engines=None , names=None))
    
    output = []
    
    # iterate over the dictionaries in the list

    for dictionary in raw:

        # grab the elements of the dictionary 

        dict_values = list(dictionary.values())[0]
        if type(dict_values) != list:
            continue
        # add those elements (if any) that are actually urls to the output list

        for value in dict_values:
            if re.match(url_regex, value):
                output.append(value)
    return output


#----------
#   main
#----------

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: ./ezenum.py [domain file] (brute)")
        quit()
    
    fp1 = open(sys.argv[1])
    domains = fp1.read().split('\n')
    
    if domains[-1] == '':
        domains = domains[:-1]
    
    for domain in domains:
        print(f"[*] Scraping the web for subdomains of {domain}, the could take a while...")
        if len(sys.argv) == 3 and sys.argv[2] == 'brute':
            subdomains = get_subdomains(brute=True) 
        else:
            subdomains = get_subdomains(brute=False)
        
        print(f"[*] Here are all the subdomains of {domain} I could find: ")

        ips = []
        for subdomain in subdomains:
            try:
                ips.append(socket.gethostbyname(subdomain))
                print(f"{subdomain}:{ips[-1]}") 
            except:
                print(f"{subdomain}:***DNS LOOKUP FAILED***")
