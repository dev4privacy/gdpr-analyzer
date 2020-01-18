#!/usr/bin/env python3

from platform import python_version
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

from mozprofile import FirefoxProfile  # temporary
import glob  # temporary
import sqlite3  # temporary
import shutil  # temporary

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


def get_content(target):
    # TODO "with browser" rather than following to use clean session and quit automatically

    # create new profile to pass to splinter
    profile_name = "/tmp/gdpr-analyzer/gdpr-analyzer.default"
    gdpr_analyzer_profile = FirefoxProfile(profile=profile_name)  # TODO define profile_pref here rather than after

    # debug
    # print(gdpr_analyzer_profile)
    # print(gdpr_analyzer_profile.profile)

    # TODO !!! get the name of the repo create in /tmp to check the cookie db !!!

    browser = Browser('firefox', profile=profile_name, timeout=1000, wait_time=200, profile_preferences={
        "network.cookie.cookieBehavior": 0})  # not to block third cookies and trackers

    browser.visit(target)

    # only gives us first party cookies
    # content_cookies = browser.cookies.all(verbose=True)

    # sad trick shot to access cookies database only work for linux because of path
    profile_files = glob.glob('/tmp/rust_mozprofile*')
    latest_profile = max(profile_files, key=os.path.getctime)

    # to debug
    # print(latest_profile)

    # copy database because we can not access to the one which is temporary create
    db_source = latest_profile + "/cookies.sqlite"
    db_destination = "/tmp/gdpr-analyzer/cookies.sqlite"
    shutil.copyfile(db_source, db_destination)

    content_html = browser.html

    browser.quit()

    # get cookie content from db
    con = sqlite3.connect(db_destination)
    cur = con.cursor()
    cur.execute("SELECT * FROM moz_cookies")
    rows = cur.fetchall()

    content_cookies = []
    for cookie in rows:
        content_cookies.append(cookie)

    con.close()

    # to debug
    # print(content_cookies)

    return content_cookies, content_html



def cookie(content_cookies, target):
    result = cookie_evaluate(content_cookies, target)
    return result


def web_beacon(content_html):
    beacon_score, beacon_info = find_beacon(content_html)
    result = json_parser(beacon_score, beacon_info)
    return result


def crypto(target):
    crypto = TransmissionSecurity(target)
    crypto.evaluate()
    return crypto.json_parser()


def full(content_cookies, content_html, target):
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


def start():
    parser = argparse.ArgumentParser(description='Description')

    parser.add_argument('url', help='Target URL')
    parser.add_argument('name', help='Owner name')
    parser.add_argument('-f', '--full', help='Get Full Analysis, Test All Available Options', action='store_true')
    parser.add_argument('-c', '--cookie', help=' Analyse the cookies and generate the score', action='store_true')
    parser.add_argument('-w', '--webbeacon', help='Check for the presence of web beacon', action='store_true')
    parser.add_argument('-t', '--crypto', help='Evaluate the transmision security', action='store_true')
    parser.add_argument('-r', '--report', help=' Generate a pdf report', action='store_true')
    parser.add_argument('-j', '--json', help='Export the result in json', action='store_true')

    args = parser.parse_args()
    name = args.name
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
            #result_crypto = '{"security_transmission": {"hostname": "www.deepl.com", "grade": "B", "note": 23, "protocol": {"TLSv1": "YES", "TLSv1_1": "YES", "TLSv1_2": "YES", "TLSv1_3": "NO", "SSLv2": "UNKNOW", "SSLv3": "UNKNOW", "score": 8}, "key": {"score": 1, "size": 2048, "type": "RSA"}, "cipher": {"TLSv1": ["DHE-RSA-AES256-SHA", "ECDHE-RSA-AES256-SHA"], "TLSv1_1": ["DHE-RSA-AES256-SHA", "ECDHE-RSA-AES256-SHA"], "TLSv1_2": ["DHE-RSA-AES256-SHA", "DHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"]}, "certificate": {"score": 4, "type": "UNKNOW", "not_before": "Mon, 24 Jul 2017 00:00:00 ", "not_after": "Thu, 23 Jul 2020 23:59:59 ", "sign_algo": "sha256WithRSAEncryption", "issued_to": "*.deepl.com", "issued_by": "COMODO RSA Domain Validation Secure Server CA"}}}'
            result.update(json.loads(result_crypto))

    result_target = "reports"

    if args.report or args.json:
        try:
            if not os.path.exists(result_target):
                os.mkdir(result_target)
        except OSError:
            print("{}Error : The folder '{}'(to save result) not exist and failed to create{}".format(bcolors.RED,
                                                                                                      folder_target,
                                                                                                      bcolors.RESET))
    if args.report:
        if result is None:
            print("{}[X] Error : No result available{}".format(bcolors.RED, bcolors.RESET))
        else:
            path_report = result_target + "/gdpranalyzer_" + name + "_" + target.netloc + ".pdf"
            generate_report(target.netloc, name, json.dumps(result), path_report)

    if args.json:
        print("{}[-] Generate the JSON{}".format(bcolors.RESET, bcolors.RESET))
        if result is None:
            print("{}[X] Error : No result available{}".format(bcolors.RED, bcolors.RESET))
        else:
            path_json = result_target + "/gdpranalyzer_" + name + "_" + target.netloc + ".json"
            with open(path_json, 'w') as outfile:
                json.dump(result, outfile)
            print("{}[-] JSON generated, it is stored in {}{}".format(bcolors.GREEN, path_json, bcolors.RESET))


'''
def entry_point():
    try:
        start()
    except KeyboardInterrupt:
        print('\n\n\033[93m[!] ctrl+c detected from user, quitting.\n\n \033[0m')
    except Exception as e:
        print(e)
'''

if __name__ == '__main__':
    if python_version()[0:3] < '3.7':
        print('{}[!] Make sure you have Python 3.7+ installed, quitting.{}'.format(bcolors.YELLOW, bcolors.RESET))
        sys.exit(1)

    start()
