from bs4 import BeautifulSoup
from css2json import css2json
from splinter.browser import Browser
import mimetypes
import requests
import json
import re
import cssutils

MDL_URL = "http://www.malwaredomainlist.com/mdlcsv.php"
MD_DOMAIN_URl = "http://www.malware-domains.com/files/justdomains.zip"
BL_DOMAIN_URL = "https://sebsauvage.net/hosts/hosts"


def find_beacon(url):
    """find suspicious fields in beacon <img/>, return the dict with how many factors there are"""
    web_beacon = []
    beacon_factors = {}
    # style_css = []
    # bl_matches = []
    blacklist_nb = 0
    size_nb = 0
    position_nb = 0
    hidden_nb = 0

    bl_list = bl_website()
    if bl_list is False:
        print("No response from the BL website\n")
    # get request
    browser = Browser('firefox')
    visit = browser.visit(url)
    content = browser.html
    browser.quit()
    if content != "":
        # return all the CSS sources present in the <link/> beacon
        css_src = find_css(content)
        # parse the html content
        soup = BeautifulSoup(content, features="html.parser")
        # find all the <img/> beacons
        image_element = [img for img in soup.find_all('img')]
        style_element = [style for style in soup.find_all('style')]

        if image_element:
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
                    style = image["style"]
                except KeyError:
                    style = ""
                try:
                    id_img = image["id"]
                except KeyError:
                    id_img = ""
                try:
                    class_img = image["class"]
                except KeyError:
                    class_img = ""
                # check if the source is blacklisted
                if src != "" and bl_list is False:
                    bl_matches = check_domains(src, bl_list)
                    if bl_matches:
                        blacklist_nb = blacklist_nb+1
                        web_beacon.append(src)
                # check if there are so suspicious words on the fields
                # check the style field
                if style != "":
                    find_style = check_style(style)
                    for h in range(len(find_style)):
                        if find_style[h] == "hidden":
                            hidden_nb = hidden_nb + 1
                            web_beacon.append(src)
                        if find_style[h] == "position":
                            position_nb = position_nb + 1
                            web_beacon.append(src)
                # check width/height fields
                if width < 3 or height < 3:
                    size_nb = size_nb + 1
                    web_beacon.append(src)
                # check the content of the CSS pages
                else:
                    if id_img != "" and src != "":
                        for url in css_src:
                            find_hidden = find_hidden_element(url, id_img)
                            for j in range(len(find_hidden)):
                                if find_hidden[j] == "hidden":
                                    hidden_nb = hidden_nb+1
                                    web_beacon.append(src)
                                if find_hidden[j] == "position":
                                    position_nb = position_nb+1
                                    web_beacon.append(src)
                    if id_img != "" or class_img != "" and src != "":
                        if style_element:
                            for k in style_element:
                                v = str(k)
                                soup = BeautifulSoup(v, features="html.parser")
                                a_style = str(soup.find('style'))
                                find_hidden_style = find_hidden_style_element(a_style, id_img)
                                for l in range(len(find_hidden_style)):
                                    if find_hidden_style[l] == "hidden":
                                        hidden_nb = hidden_nb + 1
                                        web_beacon.append(src)
                                    if find_hidden_style[l] == "position":
                                        position_nb=position_nb + 1
                                # TODO size in CSS

    else:
        print("No answer from the web site")

    beacon_factors["position"] = position_nb
    beacon_factors["size"] = size_nb
    beacon_factors["blacklist"] = blacklist_nb
    beacon_factors["hidden"] = hidden_nb
    # print(web_beacon)
    return beacon_factors


def cut_url(srcs):
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
    css_src = []
    soup = BeautifulSoup(content, features="html.parser")
    link = [link for link in soup.find_all('link')]
    for i in link:
        links = str(i)
        soup = BeautifulSoup(links, features="html.parser")
        a_link = soup.find('link')
        try:
            href = a_link["href"]
        except KeyError:
            href = ""

        if ".css" in href:
            if href not in css_src:
                css_src.append(href)
    return css_src


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


def find_hidden_element(url, element):
    """parse the CSS page"""
    visibility = {
        "display": "none",
        "visibility": "hidden",
        "border-style": "none"
    }
    position = {
        "position": "absolute"
    }
    location = {
        "left": "-", "right": "-", "top": "-"
    }
    pos = False
    result = []
    hidden = []
    tmp = requests.get(url).content.decode("utf-8")
    tmp_json = css2json(tmp)
    json_data = json.loads(tmp_json)
    for json_key, json_val in json_data.items():
        if element in json_key:
            for element_key, element_val in visibility.items():
                for find_key, find_val in json_data[json_key].items():
                    if element_key in find_key and element_val in find_val:
                        hidden.append(element_val)
            for position_key, position_val in position.items():
                for find_key, find_val in json_data[json_key].items():
                    if position_key in find_key and position_val in find_val:
                        pos = True
            if pos:
                for element_key, element_val in location.items():
                    for find_key, find_val in json_data[json_key].items():
                        if element_key in find_key and element_val in find_val:
                            result.append("position")
    if hidden:
        result.append("hidden")
    return result


def find_hidden_style_element(content, element):
    """parse the CSS in style beacons """
    visibility = {
        "display": "none",
        "visibility": "hidden",
        "border-style": "none"

    }
    position = {"position": "absolute"}
    location = {
        "left": "-",
        "right": "-",
        "top": "-"}
    pos = False
    result = []
    json_keys = []
    css_dct = {}
    a = ">"
    b = "</style>"
    # remove all occurrences streamed comments (/*COMMENT */) from string
    content = re.sub(re.compile("/\*.*?\*/", re.DOTALL), "", content)
    begin = content.find(a) + len(a)
    end = content.find(b)
    content_without_style = content[begin:end]
    # print(content_without_style)
    sheet = cssutils.parseString(content_without_style)
    style_tmp = {}
    for rule in sheet:
        print(rule)
        selector = rule.selectorText
        styles = rule.style.cssText
        sep_semicolon = styles.split(";\n")
        for i in sep_semicolon:
            sep_2dots = i.split(":")
            style_tmp[sep_2dots[0]] = sep_2dots[1].strip(" ")
            css_dct[selector] = style_tmp
    j = json.dumps(css_dct)
    json_data = json.loads(j)

    for json_key, json_val in json_data.items():
        json_keys.append(json_key)
        if element in json_key:
            for element_key, element_val in visibility.items():
                for find_key, find_val in json_data[json_key].items():
                    if element_key in find_key and element_val in find_val:
                        if json_key not in json_keys:
                            result.append("hidden")
            for position_key, position_val in position.items():
                for find_key, find_val in json_data[json_key].items():
                    if position_key in find_key and position_val in find_val:
                        pos = True
            if pos:
                for element_key, element_val in location.items():
                    for find_key, find_val in json_data[json_key].items():
                        if element_key in find_key and element_val in find_val:
                            if json_key not in json_keys:
                                result.append("position")

    return result


def bl_website():
    """request BL website et return list of domains"""
    site = requests.get(BL_DOMAIN_URL)
    if site.status_code is 200:
        html = site.text
        a = "# Blocked domains:\n"
        begin = html.find(a) + len(a)
        end = -48
        bl = html[begin:end]
        found = re.sub(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', '', bl)
        bl_domains = found.split("\n ")
        return bl_domains
    else:
        return False


def check_domains(url, bl_list):
    """Check suspicious url if it's present on blacklists"""
    result = []
    re_domain = re.search(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", url)
    url_domain = re_domain.group()
    for i in bl_list:
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


print(find_beacon("http://localhost:8000/pageNoScript.html"))
