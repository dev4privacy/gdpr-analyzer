import mimetypes
import requests
from bs4 import BeautifulSoup
from css2json import css2json
from splinter.browser import Browser
import json
import re

MDL_URL = "http://www.malwaredomainlist.com/mdlcsv.php"
MD_DOMAIN_URl = "http://www.malware-domains.com/files/justdomains.zip"
BL_DOMAIN_URL = "https://sebsauvage.net/hosts/hosts"

def find_beacon(url):
    """find suspicious fields in beacon <img/>, return the dict with how many factors there are"""
    web_beacon = []
    beacon_factors = {}
    style_css = []
    BL_matches = []
    blacklist_nb = 0
    size_nb = 0
    position_nb = 0
    hidden_nb = 0

    BL_list = BL_website()
    if BL_list == False:
        print("No response from the BL website\n")
    # get request
    browser = Browser('firefox')
    visit = browser.visit(url)
    content = browser.html
    browser.quit()
    if content != "":
        # return all the CSS sources present in the <link/> beacon
        cssSRCS = find_css(content)
        # parse the html content
        soup = BeautifulSoup(content, features="html.parser")
        # find all the <img/> beacons
        image_element = [img for img in soup.find_all('img')]
        style_element = [style for style in soup.find_all('style')]

        if image_element != []:
            # check all the <img/>
            for i in image_element:

                images = str(i)
                soup = BeautifulSoup(images, features="html.parser")
                image = soup.find('img')
                try:
                    src = image["src"]
                except KeyError:
                    src = ""
                try:
                    # extract only digits
                    width = re.match(r'^[0-9]+', image["width"])
                    width = int(width.group())
                except KeyError:
                    width = 999
                try:
                    # extract only digits
                    height = re.match(r'^[0-9]+', image["height"])
                    height = int(height.group())
                except KeyError:
                    height = 999
                try:
                    style = iage["style"]
                except KeyError:
                    style = ""
                try:
                    id = image["id"]
                except KeyError:
                    id = ""
                try:
                    classIMG = image["class"]
                except KeyError:
                    classIMG = ""
                # check if the source is blaclisted
                if src != "" and BL_list != False:
                    BL_matches = check_domains(src, BL_list)
                    if BL_matches != []:
                        blacklist_nb = blacklist_nb+1
                        web_beacon.append(src)
                # check if there are so suspicious words on the fields
                # check the style field
                if style != "":
                    find_style = check_style(style)
                    for i in range(len(find_style)):
                        if find_style[i] == "hidden":
                            hidden_nb=hidden_nb+1
                            web_beacon.append(src)
                        if find_style[i] == "position":
                            position_nb=position_nb+1
                            web_beacon.append(src)
                # check width/height fields
                if width < 3 or height < 3:
                    size_nb=size_nb+1
                    web_beacon.append(src)
                # check the content of the CSS pages
                else:
                    if id != "" and src != "":
                        for url in cssSRCS:
                            find_hidden = find_hidden_element(url,id)
                            for i in range(len(find_hidden)):
                                if find_hidden[i] == "hidden":
                                    hidden_nb=hidden_nb+1
                                    web_beacon.append(src)
                                if find_hidden[i] == "position":
                                    position_nb=position_nb+1
                                    web_beacon.append(src)

    else:
        print("No answer from the web site")

    beacon_factors["position"]=position_nb
    beacon_factors["size"]=size_nb
    beacon_factors["blacklist"]=blacklist_nb
    beacon_factors["hidden"]=hidden_nb
    # print(web_beacon)
    return beacon_factors

def cutURL(srcs):
    """cut URL and return the last part"""
    file = []
    for i in srcs:
        file.append(i.rsplit('/', 1)[-1])
    return file


def guess_image(file):
    """guess image"""
    for i in file:
        mime = mimetypes.guess_type(i)
        ext = mime[0].split('/')[0]
        if ext == "image":
            print(" {} : image_elementage detected".format(i))
        else:
            print("{} This is not a image, maybe a tracker".format(i))

def find_css(content):
    """find all the CSS pages in the <link/> beacons"""
    cssSrcs = []
    soup = BeautifulSoup(content, features="html.parser")
    link = [link for link in soup.find_all('link')]
    for i in link:
        links = str(i)
        soup = BeautifulSoup(links, features="html.parser")
        aLink = soup.find('link')
        try:
            href = aLink["href"]
        except KeyError:
            href = ""

        if ".css" in href:
            if href not in cssSrcs:
                cssSrcs.append(href)
    return cssSrcs

def check_style(style):
    """parse the Style and check the content"""
    result = []
    if "hidden" in style or "none" in style:
        result.append("hidden")
    if "position" in style and "absolute" in style:
        elements = style.split(";")
        for i in elements:
            if "left" in i or "right" in i or "top" in i:
                # TODO DL picture and check if the size and the value match
                element = i.split(":")
                if "-" in element[1]:
                    result.append("position")
                    return result
    return result

def find_hidden_element(url,element):
    """parse the CSS page"""
    visibility = {
        "display" : "none",
        "visibility": "hidden",
        "border-style" : "none"

    }
    position = { "position" : "absolute"}
    location = { "left" : "-",
                 "right" : "-",
                 "top" : "-"}

    result = []
    hidden = []
    tmp = requests.get(url).content.decode("utf-8")
    json_data = json.loads(css2json(tmp))

    for json_key,json_val in json_data.items():
        if element in json_key:
            for element_key,element_val in visibility.items():
                for find_key,find_val in json_data[json_key].items():
                    if element_key in find_key and element_val in find_val:
                        hidden.append(element_val)
            for position_key,position_val in position.items():
                for find_key,find_val in json_data[json_key].items():
                    if position_key in find_key and position_val in find_val:
                        pos = True
            if pos == True:
                for element_key,element_val in location.items():
                    for find_key,find_val in json_data[json_key].items():
                        if element_key in find_key and element_val in find_val:
                            result.append("position")
    if hidden != []:
        result.append("hidden")
    return result

def BL_website():
    """request BL website et return list of domains"""
    result = []
    site = requests.get(BL_DOMAIN_URL)
    if site.status_code is 200:
        html = site.text
        a = "# Blocked domains:\n"
        begin = html.find(a) + len(a)
        end = -48
        BL = html[begin:end]
        found = re.sub(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})','', BL)
        BL_domains = found.split("\n ")
        return BL_domains
    else:
        return False

def check_domains(url, BL_list):
    """Check suspicious url if it's present on blacklists"""
    result = []
    re_domain = re.search(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", url)
    url_domain = re_domain.group()
    for i in BL_list:
        if i == url_domain:
            result.append("blacklist")
    return result
# the user enter the URL he wants to test, return the URL
def choose_url():
    default_url = "https://www.privatesportshop.fr/"
    # default_url = "https://www.foxnews.com/"
    # default_url = "https://www.facebook.com/"
    url = input("Default URL is {}\nChoose URL : ".format(default_url))

    if url == "":
        url = default_url
    return url

print(find_beacon("https://www.privatesportshop.fr/"))
