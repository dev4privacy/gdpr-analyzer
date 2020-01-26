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
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import platform

from mozprofile import FirefoxProfile
import glob
import sqlite3
import shutil

from modules.crypto.crypto import TransmissionSecurity
from modules.report.generate_report import generate_report
from modules.web_beacon.web_beacon import find_beacon, json_parser
from modules.cookies.cookies import cookie_evaluate


class bcolors:
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
%s""" % (bcolors.CYAN, bcolors.RESET))


def get_content(target):
    """
    Get html, css and cookies from the target site
    :param target: the target site
    :return: content_cookies, content_html
    """

    print("{}[-] Retrieving website content {}".format(bcolors.RESET, bcolors.RESET))
    # create a new profile so as not to mix the user's browsing info with that of the analysis
    profile_conf_name = "/tmp/gdpr-analyzer/gdpr-analyzer.default"
    FirefoxProfile(profile=profile_conf_name)

    # define profile preferences
    browser = Browser('firefox', headless=True, profile=profile_conf_name, timeout=1000, wait_time=200,
                      profile_preferences={"network.cookie.cookieBehavior": 0})

    # navigation run
    with browser:
        browser.visit(target)

        # only gives us first party cookies
        # content_cookies = browser.cookies.all(verbose=True)

        # sad trick shot to access cookies database only work for linux because of path
        paterform = platform.system()
        if paterform == "Darwin":
            profile_repo = glob.glob('/var/folders/sd/*/T/rust_mozprofile*')
        else:
            profile_repo = glob.glob('/tmp/rust_mozprofile*')
            
        latest_profile_repo = max(profile_repo, key=os.path.getctime)

        # copy database because we can not access to the one which is temporary create
        db_source = latest_profile_repo + "/cookies.sqlite"
        db_destination = "/tmp/gdpr-analyzer/cookies.sqlite"
        shutil.copyfile(db_source, db_destination)

        content_html = browser.html

    # get cookie content from db
    con = sqlite3.connect(db_destination)
    cur = con.cursor()
    cur.execute("SELECT * FROM moz_cookies")
    rows = cur.fetchall()

    content_cookies = []
    for cookie in rows:
        content_cookies.append(cookie)

    con.close()

    print("{}[-] Website content obtained {}".format(bcolors.GREEN, bcolors.RESET))

    return content_cookies, content_html


def cookie(content_cookies, target):
    """
    Starts the cookies process
    :param content_cookies: list of cookies
    :param target: the target site
    :return: result
    """

    print("{}[-] Checking cookies {}\n".format(bcolors.CYAN, bcolors.RESET))
    result = cookie_evaluate(content_cookies, target)
    return result


def web_beacon(content_html):
    """
    Starts the web beacons process
    :param content_html: html content
    :return: result
    """

    print("{}[-] Checking web beacon{}\n".format(bcolors.CYAN, bcolors.RESET))
    beacon_score, beacon_info = find_beacon(content_html)
    result = json_parser(beacon_score, beacon_info)
    return result


def crypto(target):
    """
    Starts the transmission security process
    :param target: the target site
    :return: result
    """

    print("{}[-] Checking transmission security {}\n".format(bcolors.CYAN, bcolors.RESET))
    crypto = TransmissionSecurity(target)
    crypto.evaluate()
    return crypto.json_parser()


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

    print("{}[-] Checking the url{}".format(bcolors.RESET, bcolors.RESET))
    if not (target.startswith('//') or target.startswith('http://') or target.startswith('https://')):
        target_parse = urlparse('//' + target, 'https')
    else:
        target_parse = urlparse(target, 'https')
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
        r = requests.get(target_parse.geturl(), headers=headers, verify=False)
        r.raise_for_status()
    except ConnectionError as e:
        print("{}[X] Error : Failed to establish a connection, verify that the target exists{}".format(bcolors.RED,
                                                                                                       bcolors.RESET))
        sys.exit(1)
    except HTTPError as e:
        print("{}[X] Error : {}{}".format(bcolors.RED, e, bcolors.RESET))
        sys.exit(1)
    else:
        print("{}[-] url OK{}".format(bcolors.GREEN, bcolors.RESET))
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
        if rank is None or grade > rank :
            rank = grade
    if "web_beacons" in result:
        grade = result["web_beacons"]["grade"]
        if rank is None or grade > rank :
            rank = grade
    if "security_transmission" in result:
        grade = result["security_transmission"]["grade"]
        if rank is None or grade > rank :
            rank = grade

    print("\n{}{}{}WEBSITE GRADE :{} {}\n".format(bcolors.CYAN, bcolors.UNDERLINE, bcolors.BOLD, bcolors.RESET, rank))

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
            print("{}Error : The folder '{}'(to save result) not exist and failed to create{}".format(bcolors.RED,
                                                                                                      result_target,
                                                                                                      bcolors.RESET))
    if args.report:
        if result is None:
            print("{}[X] Error : No result available{}".format(bcolors.RED, bcolors.RESET))
        else:
            path_report = result_target + "/gdpranalyzer_" + name + "_" + target.netloc + ".pdf"
            generate_report(name, json.dumps(result), path_report)

    if args.json:
        print("{}[-] Generate the JSON{}".format(bcolors.RESET, bcolors.RESET))
        if result is None:
            print("{}[X] Error : No result available{}".format(bcolors.RED, bcolors.RESET))
        else:
            path_json = result_target + "/gdpranalyzer_" + name + "_" + target.netloc + ".json"
            with open(path_json, 'w') as outfile:
                json.dump(result, outfile)
            print("{}[-] JSON generated, it is stored in {}{}".format(bcolors.GREEN, path_json, bcolors.RESET))

if __name__ == '__main__':
    if platform.python_version()[0:3] < '3.7':
        print('{}[!] Make sure you have Python 3.7+ installed, quitting.{}'.format(bcolors.YELLOW, bcolors.RESET))
        sys.exit(1)

    start()
