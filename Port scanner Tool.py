#!/usr/bin/python
import re
import socket
import optparse  # ALLOWS US TO TAKE INPUT FROM CMD Line diorectly, and parse them then use them in out code
from threading import *  # threading functionalities
import base64
import chardet
import select
import os
import subprocess as subprocess
import requests
from bs4 import BeautifulSoup
from lxml import html
from selenium.webdriver import Firefox


# takes arguments from terminal
def getArguments():
    parser = optparse.OptionParser("Usage of this scanner is: -t <target host> -p <Port number>\nExample of usages:\n\t[+] python compScan.py -t 192.168.59.152 -p 21\n\t[+] python compScan.py -t 192.168.59.0/24 -p 21  ")  # creating a parser
    # object

    # now we add options to our parser object (target IP and target port)
    parser.add_option("-t", "--target_host", dest='targetHost', help="IP address of target host to attack")
    parser.add_option("-p", "--target_port", dest='targetPort', help="Port number of target host to attack.\nPut "
                                                                     "value -1 to scan all ports")

    (options, arguments) = parser.parse_args()  # puts the user input into variables
    if not options.targetHost:
        parser.error("[-] Please specify the target host !")
    elif not options.targetPort:
        parser.error("[-] No port number provided.")
        # options.targetPort = -1

    return options # include the target host and target port


# gets the service name running on a port
def getSevByPorts(port, protocol):  # returns srevice name on a port

    try:
        # print("simple get")
        service = socket.getservbyport(port, protocol)

    except:
        service = "Can not find service name !"

    return service


# gets deatiled information about a service running on a port, by grabbing its banner
def portDetails(port, ip):
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    t.connect((ip, port))
    t.send("GET / HTTP/1.0\r\n\r\n")  # we append these escape charcter to tell the request that this is the end of
    # our request

    t.setblocking(0) # this is set to false, which means non-blocking mode.
    # In blocking socket mode, a system call event halts the execution until an appropriate reply has been received.
    # In non-blocking sockets, it continues to execute even if the system call has been invoked and deals with its reply
    # appropriately late


    ready = select.select([t], [], [], 10)


    if ready[0]: # if there is data received
        # print(ready[0])
        msg = t.recv(1024) # recv 1024 bytes of the response we got
    else:
        finalMessage = "Not available"
        return finalMessage

    # now the banners might be encoded.
    # I try to detect the encoding, then decode it.
    the_encoding = chardet.detect(msg)['encoding'] # {'encoding':'value of encoding found'}


    # chardet is The Universal Character Encoding Detector
    # chardet returns a dictionary with a default key of 'encoding', we write encoding cuz we want its value

    if the_encoding is not "None": # if there is no encoding used
        # print("Encoding used: " + str(the_encoding))
        return msg.split('\n')[0]
    else:
        newMsg = msg.decode(the_encoding).encode('utf-8')
        finalMessage = newMsg.split('\n')[0]

    t.close() # closing the open socket

    return finalMessage


# function to filter and prepare service name to be queried from various databases
def replaceCharsWithSpace(searchItem):
    if len(searchItem) < 2:
        return " "
    else:
        my_new_string = re.sub('[_)(/]', ' ', searchItem)
        # print(my_new_string)
        searchArray = my_new_string.split()
        url = ""
        for x in searchArray:
            url = url + x + "+"
        # print(url)
        return url # RETURNS e.g, FTP+2.2.3


# function to search the databse of CVE.mitre.org
def getCVEVulns(url):
    # get div "table with rules"
    # get all of the td in pairs ( CVE File name, description )
    # display to user
    driver = Firefox(executable_path='/root/Downloads/geckodriver')  # creating driver
    driver.get(url)  # requesting our page, this is like request.get("url")

    content = driver.page_source # page source of the response we got

    parsed_page = BeautifulSoup(content, features="lxml")
    mainTable = parsed_page.find("div", attrs={'id': 'TableWithRules'})
    if mainTable.findAll('td'): # If no results were found in the CVE database
        tdList = mainTable.findAll("td")
        driver.quit()
        x = 0
        for td in tdList:
            # print("TD: "+td.text)
            x = x + 1
            if x % 2 == 0:
                print("Description: " + td.text)
            else:
                print("CVE record: " + td.text)
            print("------------------------------------------")
    else:
        driver.quit()
        return True # means to look in the Rapid7 database


# function to search the database of Rapid7
def getRapid7Vuln(url):
    driver = Firefox(executable_path='/root/Downloads/geckodriver')  # creating driver
    driver.get(url)  # requesting our page

    content = driver.page_source
    parsed_page = BeautifulSoup(content, features="lxml")
    mainTable = parsed_page.find("section", attrs={'class': 'vulndb__results'})
    driver.quit()
    if mainTable:
        targetDivs = mainTable.findAll("div", attrs={'class': 'resultblock__info-title'})
        for div in targetDivs:
            targetTitle = str(div.text).replace(" ", '')
            print(targetTitle)
            print("--------------------------------------------------------------")
    else:
        print("No vulnerabilities were found !")


# displays the information of a port ( port No.     State       Service         Details)
# then shows if any vulnerabilities exists in the service or not
def connscan(targetHost, targetPort):  # scans a single port
    try:
        #sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creating a socket
        # AF_INET --> IPv4   SOCK_STREAM --> Tcp communication
        #sock.connect((targetHost, targetPort)) # connecting this socket to a target port in a target host
        portShortName = getSevByPorts(int(targetPort), 'tcp')  # e.g., ftp, smtp, ssh
        portShortDescription = str(portDetails(targetPort, targetHost))
        print(str(targetPort) + "\t\t" + "Open\t\t  " + portShortName + "\t\t\t" + portShortDescription)

        # now we add a short description of the service running on the port
        url = "www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"
        shortDescription = getShortDescription(url, portShortName)
        if shortDescription:  # if the service is found on the first page of the website:
            print("\n[+] Short description: " + shortDescription)
        else:  # if the service is not found in the first page in the website:
            for number in range(2, 144):  # we check all other pages untill we find it
                url = url.split("?")[0]
                newUrl = url + "?&page=" + str(number)
                newDesc = getShortDescription(newUrl, portShortName)
                if newDesc:
                    print("[+] Short description: " + newDesc)
                    break

        # we can go ahead and show
        # vulnerabilities we find while our code automatically looks up several database
        # we then check CVE
        serviceName = replaceCharsWithSpace(portShortDescription)  # returns enhanced service name that will be sent
        # to the CVE and Rapid7 databases to look i n
        if serviceName == " " or serviceName == "Not+available+":
            print("[-] No service name found !")
        else:
            urlCVE = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + serviceName
            print("\n[+] Vulnerabilities detected: \n")
            # we then check Rapid7
            if getCVEVulns(urlCVE):
                urlRapid7 = "https://www.rapid7.com/db/?q=" + serviceName + "&type="  # custom url format for rapid7
                getRapid7Vuln(urlRapid7)




        # now we add analysis and possible threats to the ports in general
        if serviceName == " ":
            print("[-] No service name found !")
        else:
            urlAnalysis = "http://www.speedguide.net/port.php?port="
            portAnalysis = getAnalysisOfPort(urlAnalysis, str(targetPort))
            print("[+] Port analysis and summary: \n" + portAnalysis)



    except socket.error:
        print("Port " + str(targetPort) + "/tcp is closed")
    finally:
        print("[+] Scan finished !")


# same as connscan but for multiple ports, I use it becuase I dont want to show closed ports to the user
def connscan2(targetHost, targetPort):  # scans multiple ports
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((targetHost, targetPort))
        print(str(targetPort) + "\t\t" + "Open\t\t  " + getSevByPorts(int(targetPort), 'tcp')) + "\t\t\t" + str(
            portDetails(targetPort, targetHost))

    except:
        exit


# identifies host that Im probing,
# Not used anymore in my code.
def identifyHost(targetHost, targetPort):
    if checkIfAlive(targetHost):
        targetPort = int(targetPort)
        try:
            targetIP = socket.gethostbyname(targetHost)
        except:
            print("Unknown host is " + targetHost)
        try:
            targetName = socket.gethostbyaddr(targetIP)
            print("[+] Scan results for " + targetName)
        except:
            print("[+] Scan results for " + str(targetIP))
    else:
        pass


# checks if target is alive before probing
def checkIfAlive(targetHost):
    HOST_UP = True if os.system("ping -c 2 " + str(targetHost) + " > /dev/null") is 0 else False # interacts with the
    # operating system of our machine
    # /dev/null hides the console output produced by os.system("ping ... ")
    # the condition works because if the ping fails it will return an error which is not a 0
    # HOST_UP = subprocess.check_call(['ping', '-c','1','192.168.59.111'], stdout=False, stderr=subprocess.STDOUT)

    # print("Host up ? "+str(HOST_UP))
    return HOST_UP


# backbone funtion that starts the scanning process
def portScanner(targetHost, targetPort):
    targetPort = int(targetPort)
    #    targetIP = socket.gethostbyname(targetHost)
    # except:
    #    print("Unknown host is " + targetHost)
    # try:
    #    targetName = socket.gethostbyaddr(targetIP)
    #    print("[+] Scan results for " + targetName)
    # except:
    #   print("[+] Scan results for " + str(targetIP))

    # print("[+] Scan results for --> " + targetHost)
    print("\nPort\t\tStatus\t\t Service\t\tDetails")
    print("-----------------------------------------------------------------")
    if '/' in targetHost: # User wants to scan a subnet of the network (192.168.59.0/24)
        targetHostStr = str(targetHost)
        parts = targetHostStr.split('/')
        networkIP = parts[0]
        sub_net = int(parts[1])
        # print("PArt 1:" +networkIP)
        # print("PArt 2:" +str(sub_net))
        if sub_net == 24:
            subnetToChange = re.findall('[0-9]+.[0-9]+.[0-9]+.?([0-9]+)', networkIP)[0]
            originalNetwork = re.findall('([0-9]+.[0-9]+.[0-9]+).[0-9]+', networkIP)[0]
            # print("SUbnet to change: "+str(subnetToChange))
            # print("network to remain: "+str(originalNetwork))
            for machine in range(1, 256):
                #newSubnet = int(subnetToChange) + machine
                targetHost = originalNetwork + "." + str(machine)
                # print("im here deez: "+targetHost)
                # identifyHost(targetHost,targetPort)
                if checkIfAlive(targetHost): # checks if the target host is alive
                    print("[+] Scan results for --> " + targetHost)
                    if targetPort != -1:
                        t = Thread(target=connscan, args=(targetHost, int(targetPort))) # creates a thread
                        t.start()
                    else:
                        for port in range(1, 1000):
                            t = Thread(target=connscan2, args=(targetHost, int(port)))
                            t.start()
                targetHost = targetHostStr
    else:
        # print("[+] Scan results for --> " + targetHost)
        if checkIfAlive(targetHost):  # checks to see if the provided host is alive and reachable
            if targetPort != -1:
                t = Thread(target=connscan, args=(targetHost, int(targetPort)))
                t.start()
            else:
                for port in range(1, 1000):
                    t = Thread(target=connscan2, args=(targetHost, int(port)))
                    t.start()
        else:  # if host is not reachable
            print("[-] Host is offline")

# gets short description of a service running on a port
def getShortDescription(url, port):
    try:
        get_response = requests.get(
            'http://' + url)  # all a function called get allowing us to send a get request and we are
        # passing a url variable
        parsedHtml = BeautifulSoup(get_response.content, features="lxml")
        tdList = parsedHtml.findAll("td")  # retreiving all the table td
        desiredTd = []
        x = 0
        for td in tdList:
            x += 1  # pointer to show me on which td im on
            #print("Current TD: "+str(td)+" //// current ID: "+str(x))
            if port in td:  # if service im looking for is found in the td  ( made of several columns )
                desiredTd.append(tdList[x + 2])  # x+2 becuase the td I need is after 2 tds of the current td
                break

        if desiredTd:
            description = str(desiredTd[0]).strip('<td>,</td>')
        else:
            description = None

        return description

    except requests.exceptions.ConnectionError:
        print("Error connecting....Trying again")
        getShortDescription(url)


def getAnalysisOfPort(url, port):
    driver = Firefox(executable_path='/root/Downloads/geckodriver')  # creating driver
    driver.get(url + port)  # requesting our page

    content = driver.page_source

    parsed_page = BeautifulSoup(content, features="lxml")
    mainTable = parsed_page.find("table", attrs={'class': 'port'})

    rowsList = mainTable.findAll("tr")
    driver.quit()
    if len(rowsList[1].text) > len(rowsList[2].text):
        return rowsList[1].text
    else:
        return rowsList[2].text


def main():
    options = getArguments()  # gets the arguments from the command line (target host, target port)
    targetHost = options.targetHost  # host to attack
    targetPort = options.targetPort  # port(s) to scan
    portScanner(targetHost, targetPort)


if __name__ == '__main__':
    main()
