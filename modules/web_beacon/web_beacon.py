#!/usr/bin/env python3.7
# coding: utf-8

from bs4 import BeautifulSoup
import requests
import json
import re
import tinycss
import configparser
import os
from urllib.parse import urlparse

MDL_URL = "http://www.malwaredomainlist.com/mdlcsv.php"
MD_DOMAIN_URl = "http://www.malware-domains.com/files/justdomains.zip"
BL_DOMAIN_URL = "https://sebsauvage.net/hosts/hosts"

# take the content of config.ini
config = configparser.ConfigParser()
config.read(os.path.dirname(__file__) + '/config.ini')


class Bcolors:
    HEADER = '\033[95m'
    CYAN = "\033[36m"
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    REVERSE = "\033[;7m"


def find_beacon(content_html):
    """
    find suspicious fields in beacon <img/>, return the dict with how many factors there are
    :param content_html: url the user wants to test
    :return: info and score for web beacon
    """
    web_beacon_url = []
    # take the value for eatch category in config.ini
    position_pt = int(config['category']['position'])
    hidden_pt = int(config['category']['hidden'])
    size_pt = int(config['category']['size'])
    blacklist_pt = int(config['category']['blacklist'])
    blacklist_nb = 0
    size_nb = 0
    position_nb = 0
    hidden_nb = 0

    # display web beacon title in terminal
    print(f"{Bcolors.UNDERLINE}{Bcolors.BOLD}Detected Web beacon(s):{Bcolors.RESET}\n")
    bl_list = bl_website()
    if bl_list is False:
        print("No response from the BL website\n")

    if content_html != "":
        # return all the CSS sources present in the <link/> beacon
        css_src = find_css(content_html)
        # parse the html content
        soup = BeautifulSoup(content_html, features="html.parser")
        # find all the <img/> beacons
        image_element = [img for img in soup.find_all('img')]
        style_element = [style for style in soup.find_all('style')]

        if image_element:
            # check all the <img/>
            for i in image_element:
                web_beacon_position = False
                web_beacon_hidden = False
                web_beacon_blacklist = False
                web_beacon_size = False
                web_beacon_categories = {}
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
                except (KeyError, AttributeError):
                    width = 999
                try:
                    # extract only digits
                    height = re.match(r'^[0-9]+', image["height"])
                    height = int(height.group())
                except (KeyError, AttributeError):
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
                        web_beacon_blacklist = True

                # check if there are so suspicious words on the fields
                # check the style field
                if style != "":
                    find_style = check_style(style)
                    for h in range(len(find_style)):
                        if find_style[h] == "hidden":
                            hidden_nb = hidden_nb + 1
                            web_beacon_hidden = True

                        if find_style[h] == "position":
                            position_nb = position_nb + 1
                            web_beacon_position = True

                # check width/height fields
                if width < 3 or height < 3:
                    size_nb = size_nb + 1
                    web_beacon_size = True

                # check the content of the CSS pages
                else:
                    if id_img != "" and src != "":
                        for url in css_src:
                            find_hidden = find_hidden_element(url, id_img)
                            for j in range(len(find_hidden)):
                                if find_hidden[j] == "hidden":
                                    hidden_nb = hidden_nb+1
                                    web_beacon_position = True

                                if find_hidden[j] == "position":
                                    position_nb = position_nb+1
                                    web_beacon_position = True

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
                                        web_beacon_hidden = True

                                    if find_hidden_style[l] == "position":
                                        position_nb = position_nb + 1
                                        web_beacon_position = True
                                # TODO size in CSS

                if web_beacon_position or web_beacon_size or web_beacon_blacklist or web_beacon_hidden:
                    
                    if not (src.startswith('//') or src.startswith('http://') or src.startswith('https://')):
                        target_parse = urlparse('//' + src, 'https')
                    else:
                        target_parse = urlparse(src, 'https')

                    web_beacon_categories["url"] = src
                    web_beacon_categories["target"] = target_parse.netloc
                    web_beacon_categories["position"] = web_beacon_position
                    web_beacon_categories["size"] = web_beacon_size
                    web_beacon_categories["hidden"] = web_beacon_hidden
                    web_beacon_categories["blacklist"] = web_beacon_blacklist
                    web_beacon_url.append(web_beacon_categories)
                    print(f"\t{Bcolors.BOLD}{src}:{Bcolors.RESET}\n\t\tsize : {web_beacon_size}\tposition : "
                          f"{web_beacon_position}\thidden : {web_beacon_hidden}\tblacklist : {web_beacon_blacklist}")

    else:
        print("No answer from the web site")

    # calculate web beacon score
    position_score = position_nb * position_pt
    size_score = size_nb * size_pt
    blacklist_score = blacklist_nb * blacklist_pt
    hidden_score = hidden_nb * hidden_pt
    web_beacon_score = position_score + size_score + blacklist_score + hidden_score
    return web_beacon_score, web_beacon_url


def find_css(content):
    """
    find all the CSS pages in the <link/> beacons
    :param content: the content of the web page
    :return: css web pages
    """
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
    """
    parse the Style and check the content
    :param style: the content of the style attribute
    :return: list of factors elements find
    """
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
    """
    parse the CSS page
    :param url: url of the css page
    :param element: element need to find in the page
    :return: list of factors elements find
    """
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
    css_dct = {}
    request = requests.get(url).content.decode("utf-8")
    stylesheet = tinycss.make_parser().parse_stylesheet(request)
    for rule in stylesheet.rules:
        try:
            selector = rule.selector.as_css()
        except AttributeError:
            for i in rule.rules:
                stylesheet.rules.append(i)
                selector = None
        if selector:
            dct_style = {}
            for d in rule.declarations:
                value = ""
                for v in d.value:
                    value = value + v.as_css()
                dct_style[d.name] = value
            css_dct[selector] = dct_style
    j = json.dumps(css_dct)
    json_data = json.loads(j)
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
    """
    parse the CSS in style beacons
    :param content: the content of the style beacon
    :param element:  element need to find in the page
    :return: list of factors elements find
    """
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
    stylesheet = tinycss.make_parser().parse_stylesheet(content_without_style)
    for rule in stylesheet.rules:
        selector = rule.selector.as_css()
        dct_style = {}
        for d in rule.declarations:
            value = ""
            for v in d.value:
                value = value+v.as_css()
            dct_style[d.name] = value
        css_dct[selector] = dct_style
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
    """
    Request BL website et return list of domains
    :return: blacklist domains or None
    """
    site = requests.get(BL_DOMAIN_URL)
    # TODO replace when the website is up
    # f = open("utils/hosts.txt", "r") # TODO put absolute path
    # hosts = f.read()
    if site.status_code == 200:
        hosts = site.text
        a = "# Blocked domains:\n"
        begin = hosts.find(a) + len(a)
        end = -48
        bl = hosts[begin:end]
        found = re.sub(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', '', bl)
        bl_domains = found.split("\n ")
        return bl_domains
    else:
        return False


def check_domains(url, bl_list):
    """
    Check suspicious url if it's present on blacklists
    :param url: url need to check
    :param bl_list: blacklist domains
    :return: list of factors elements find
    """
    result = []
    re_domain = re.search(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", url)
    url_domain = re_domain.group()
    for i in bl_list:
        if i == url_domain:
            result.append("blacklist")
    return result


def calculate_grade(web_beacon_score):
    """
    calculate the grade for the website
    :param web_beacon_score: score for web beacon
    :return: web_beacon_grade
    """
    a_grade = int(config['grade']['A'])
    b_grade = int(config['grade']['B'])
    c_grade = int(config['grade']['C'])
    d_grade = int(config['grade']['D'])
    e_grade = int(config['grade']['E'])

    if web_beacon_score <= a_grade:
        web_beacon_grade = "A"
    elif web_beacon_score <= b_grade:
        web_beacon_grade = "B"
    elif web_beacon_score <= c_grade:
        web_beacon_grade = "C"
    elif web_beacon_score <= d_grade:
        web_beacon_grade = "D"
    elif web_beacon_score <= e_grade:
        web_beacon_grade = "E"
    else:
        web_beacon_grade = "F"

    # display web beacon score and grade in terminal
    print("\n{}{}Web beacon score:{} {}".format(Bcolors.BOLD, Bcolors.UNDERLINE, Bcolors.RESET, web_beacon_score))
    print("{}{}Web beacon grade:{} {}\n".format(Bcolors.BOLD, Bcolors.UNDERLINE, Bcolors.RESET, web_beacon_grade))

    return web_beacon_grade


def json_parser(web_beacon_score, web_beacon_url):
    """
    parse the results into json object
    :param web_beacon_score: score for web beacon
    :param web_beacon_url: url with categories matched
    :return: json_beacon
    """
    web_beacon = {}
    result = {}
    web_beacon_grade = calculate_grade(web_beacon_score)
    result['grade'] = web_beacon_grade
    result['score'] = web_beacon_score
    result['url'] = web_beacon_url
    web_beacon['web_beacons'] = result
    return json.dumps(web_beacon)
