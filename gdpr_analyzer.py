#!/usr/bin/env python3.7
# coding: utf-8

import sys
import os
import argparse
import json
from splinter import Browser
from urllib.parse import urlparse
import requests
from requests.exceptions import ConnectionError, HTTPError
import urllib3
import platform
import sqlite3

#from modules.crypto.crypto import TransmissionSecurity
from modules.report.generate_report import generate_report
from modules.web_beacon.web_beacon import find_beacon, json_parser
from modules.cookies.cookies import cookie_evaluate
# TODO: add to test
from modules.crypto.crypto import crypto_evaluate


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


def banner():
    """
    Print the tool's banner
    """

    print("""%s

\t  ____ ____  ____  ____                      _                    
\t / ___|  _ \|  _ \|  _ \    __ _ _ __   __ _| |_   _ _______ _ __ 
\t| |  _| | | | |_) | |_) |  / _` | '_ \ / _` | | | | |_  / _ \ '__|
\t| |_| | |_| |  __/|  _ <  | (_| | | | | (_| | | |_| |/ /  __/ |   
\t \____|____/|_|   |_| \_\  \__,_|_| |_|\__,_|_|\__, /___\___|_|   
\t                                               |___/  
%s""" % (Bcolors.CYAN, Bcolors.RESET))


def get_content(target):
    """
    Get html, css and cookies from the target site
    :param target: the target site
    :return: content_cookies, content_html
    """

    print("{}[-] Retrieving website content {}".format(Bcolors.RESET, Bcolors.RESET))

    browser = Browser('firefox', headless=True, timeout=5000, wait_time=200,
                      profile_preferences={"network.cookie.cookieBehavior": 0})

    with browser:
        browser.visit(target)

        # We cannot use the following because it doesn't retrieve third party cookies
        # content_cookies = browser.cookies.all(verbose=True)

        # Instead we do it in a hack-ish way :
        # We retrieve the cookies database from the copy of our Firefox profile made by the geckodriver
        cookies_db_of_geckodriver = browser.driver.capabilities["moz:profile"] + "/cookies.sqlite"
        cookies_db_of_firefox = browser.driver.profile.path + "/cookies.sqlite"

        # Copy the database because the original one is locked until the browser object is garbage collected
        with open(cookies_db_of_geckodriver, "rb") as gecko_db:
            with open(cookies_db_of_firefox, "wb") as firefox_db:
                firefox_db.write(gecko_db.read())

        # get cookies from Firefox's profile
        with sqlite3.connect(cookies_db_of_firefox) as con:
            cur = con.cursor()
            cur.execute("SELECT * FROM moz_cookies")
            content_cookies = cur.fetchall()

        content_html = browser.html

    print("{}[-] Website content obtained {}".format(Bcolors.GREEN, Bcolors.RESET))

    return content_cookies, content_html


def cookie(content_cookies, target):
    """
    Starts the cookies process
    :param content_cookies: list of cookies
    :param target: the target site
    :return: result
    """

    print("{}[-] Checking cookies {}\n".format(Bcolors.CYAN, Bcolors.RESET))
    result = cookie_evaluate(content_cookies, target)  # TODO divide into two functions (one to get info, other to calculate)?
    return result


def web_beacon(content_html):
    """
    Starts the web beacons process
    :param content_html: html content
    :return: result
    """

    print("{}[-] Checking web beacon{}\n".format(Bcolors.CYAN, Bcolors.RESET))
    beacon_score, beacon_info = find_beacon(content_html)
    result = json_parser(beacon_score, beacon_info)
    return result


def crypto(target):
    """
    Starts the transmission security process
    :param target: the target site
    :return: result
    """

    print("{}[-] Checking transmission security {}\n".format(Bcolors.CYAN, Bcolors.RESET))
    result = crypto_evaluate(target, 443)
    return result


def full(content_cookies, content_html, target):
    """
    Starts each process (cookie, web beacon and transmission security)
    :param content_cookies: list of cookies
    :param content_html: the html content of the target site
    :param target: the target site
    :return: full_result
    """

    result_cookie = None
    result_web_beacon = None
    result_crypto = None
    full_result = []

    result_cookie = cookie(content_cookies, target)
    result_web_beacon = web_beacon(content_html)
    result_crypto = crypto(target)

    full_result = json.loads(result_cookie)
    full_result.update(json.loads(result_web_beacon))
    full_result.update(json.loads(result_crypto))

    return full_result


def check_target(target):
    """
    Check if the URL is valid and if the target site is online
    :param target: the target site
    :return: target_parse
    """

    print("{}[-] Checking the url{}".format(Bcolors.RESET, Bcolors.RESET))
    if not (target.startswith('//') or target.startswith('http://') or target.startswith('https://')):
        target_parse = urlparse('//' + target, 'https')
    else:
        target_parse = urlparse(target, 'https')
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/50.0.2661.102 Safari/537.36'}
        r = requests.get(target_parse.geturl(), headers=headers, verify=False)
        r.raise_for_status()
    except ConnectionError as e:
        print("{}[X] Error : Failed to establish a connection, verify that the target exists{}".format(Bcolors.RED,
                                                                                                       Bcolors.RESET))
        sys.exit(1)
    except HTTPError as e:
        print("{}[X] Error : {}{}".format(Bcolors.RED, e, Bcolors.RESET))
        sys.exit(1)
    else:
        print("{}[-] url OK{}".format(Bcolors.GREEN, Bcolors.RESET))
        return target_parse


def assess_rank(result):
    """
    Assess the global rank of the site
    :param result: Concatenation of the result of each module
    :return: rank
    """

    rank = None

    if "cookies" in result:
        grade = result["cookies"]["grade"]
        if rank is None or grade > rank:
            rank = grade
    if "web_beacons" in result:
        grade = result["web_beacons"]["grade"]
        if rank is None or grade > rank:
            rank = grade
    if "security_transmission" in result:
        grade = result["security_transmission"]["grade"]
        if rank is None or grade > rank:
            rank = grade

    print("\n{}{}{}WEBSITE GRADE :{} {}\n".format(Bcolors.CYAN, Bcolors.UNDERLINE, Bcolors.BOLD, Bcolors.RESET, rank))

    return rank


def start():
    """
    Parse arguments and starts the web site analysis
    """

    banner()
    parser = argparse.ArgumentParser(description='Description')

    parser.add_argument('url', help='target URL')
    parser.add_argument('yourname', help="report owner's name")
    parser.add_argument('-f', '--full', help='get full analysis, test all available options', action='store_true')
    parser.add_argument('-c', '--cookie', help='analyse the cookies and generate the score', action='store_true')
    parser.add_argument('-w', '--webbeacon', help='check for the presence of web beacons', action='store_true')
    parser.add_argument('-t', '--crypto', help='evaluate the transmission security', action='store_true')
    parser.add_argument('-r', '--report', help='generate a pdf report', action='store_true')
    parser.add_argument('-j', '--json', help='export the result in a json file', action='store_true')

    args = parser.parse_args()
    name = args.yourname
    result = {}

    target = check_target(args.url)

    if args.webbeacon or args.cookie:
        content_cookies, content_html = get_content(target.geturl())

    if args.full or (not args.cookie and not args.webbeacon and not args.crypto):
        content_cookies, content_html = get_content(target.geturl())
        result = full(content_cookies, content_html, target.netloc)
    else:
        if args.webbeacon:
            result_web_beacon = web_beacon(content_html)
            result.update(json.loads(result_web_beacon))
        if args.cookie:
            result_cookie = cookie(content_cookies, target.netloc)
            result.update(json.loads(result_cookie))
        if args.crypto:
            result_crypto = crypto(target.netloc)
            result.update(json.loads(result_crypto))

    result_info = {}
    result_info["target"] = target.netloc
    result_info["grade"] = assess_rank(result)
    result.update(json.loads(json.dumps(result_info)))

    result_target = "reports"
    if args.report or args.json:
        try:
            if not os.path.exists(result_target):
                os.mkdir(result_target)
        except OSError:
            print("{}Error : The folder '{}'(to save result) not exist and failed to create{}".format(Bcolors.RED,
                                                                                                      result_target,
                                                                                                      Bcolors.RESET))
    if args.report:
        if result is None:
            print("{}[X] Error : No result available{}".format(Bcolors.RED, Bcolors.RESET))
        else:
            path_report = result_target + "/gdpranalyzer_" + name + "_" + target.netloc + ".pdf"
            generate_report(name, json.dumps(result), path_report)

    if args.json:
        print("{}[-] Generate the JSON{}".format(Bcolors.RESET, Bcolors.RESET))
        if result is None:
            print("{}[X] Error : No result available{}".format(Bcolors.RED, Bcolors.RESET))
        else:
            path_json = result_target + "/gdpranalyzer_" + name + "_" + target.netloc + ".json"
            with open(path_json, 'w') as outfile:
                json.dump(result, outfile)
            print("{}[-] JSON generated, it is stored in {}{}".format(Bcolors.GREEN, path_json, Bcolors.RESET))


if __name__ == '__main__':

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if platform.python_version()[0:3] < '3.7':
        print('{}[!] Make sure you have Python 3.7+ installed, quitting.{}'.format(Bcolors.YELLOW, Bcolors.RESET))
        sys.exit(1)

    start()
