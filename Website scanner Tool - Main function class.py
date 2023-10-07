#!/usr/bin/env python2

import scanner
import validators
import requests
#target_url = 'http://192.168.59.152/mutillidae/'

# target_url = "http://192.168.59.152/dvwa/" # url to metasploitable machine
#target_url = "https://www.alfaisal.edu/" # url to metasploitable machine
#https://www.alfaisal.edu/en/
data_dict = {"username":"admin", "password":"password","Login":"submit "} # used for guessing login credenatials
# in case a website requires a login

# we ask user to enter website to scan
# we then give them 2 options
# - test xss reflected in forms
# - test command injection in forms

targetSite = raw_input("Please enter target website: ")


if targetSite and validators.url(targetSite):

    vuln_scanner = scanner.Scanner(targetSite)  # creating a scanner object
    vuln_scanner.session.post("http://192.168.59.152/dvwa/login.php",
                              data=data_dict)  # logging in and starting a session

    print("Choose a fucntion from the following:")
    print("\t1- Test xss reflected in forms")
    print("\t2- Test command injection in forms")

    toolChoice = int(input("Tool choice: <1,2> ?"))
    print("------------------------------------------------------------------------------\n")

    if toolChoice == 1:
        print("[+] Links that will be tested")
        vuln_scanner.run_xss_form_scanner()
    elif toolChoice == 2:
        print("[+] Links that will be tested")
        vuln_scanner.run_command_injection_scanner()
    else:
        print("[+] Please choose a number from 1-2 !")
else:
    print("[+] Webiste address not valid !")



