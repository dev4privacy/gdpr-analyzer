#!/usr/bin/env python3

from platform import python_version
import sys
import argparse
import json
from splinter import Browser
from urllib.parse import urlparse
import requests
from requests.exceptions import ConnectionError, HTTPError

from modules.crypto.crypto import TransmissionSecurity
from modules.report.generate_report import generate_report
from modules.web_beacon import find_beacon, json_parser
from modules.cookies.cookies import cookie_evaluate

class bcolors:
    HEADER = '\033[95m'
    CYAN  = "\033[36m"
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'    
    REVERSE = "\033[;7m"

def get_content(target):
    # TODO with browser rather than following to use clean session and quit automatically
    browser = Browser('firefox', timeout=200, wait_time=200, profile_preferences={"network.cookie.cookieBehavior": 0})  # not to block third cookies and trackers

    browser.visit(target)

    # TODO we must return also third party cookies even if they are in firefox cookies...
    content_cookies = browser.cookies.all(verbose=True)
    # to bypass this problem link to splinter, possibility to get all cookies from firefox but we can have cookies from
    # user navigation...
    content_html = browser.html
    browser.quit()
    return content_cookies, content_html

def cookie(content_cookies, target):
    result = cookie_evaluate(content_cookies, target)
    return result

def webbeacon(content_html):
    beacon_score, beacon_info = find_beacon(content_html)
    result = json_parser(beacon_score, beacon_info)
    return result

def crypto(target):
    crypto = TransmissionSecurity(target)
    crypto.evaluate()
    return crypto.json_parser()

def full(content_cookies, content_html, target):
    result_cookie = None
    result_webbeacon = None
    result_crypto = None
    full_result = []

    result_cookie = cookie(content_cookies, target)
    result_webbeacon = webbeacon(content_html)
    result_crypto = crypto(target)

    full_result = json.loads(result_cookie)
    full_result.update(json.loads(result_webbeacon))
    full_result.update(json.loads(result_crypto))
    return full_result

def check_target(target):
    print("{}[-] Checking the url{}".format(bcolors.RESET, bcolors.RESET))
    if not (target.startswith('//') or target.startswith('http://') or target.startswith('https://')):
        target_parse = urlparse('//' + target, 'https')
    else: 
        target_parse = urlparse(target, 'https')
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}
        r = requests.get(target_parse.geturl(), headers=headers)
        r.raise_for_status()
    except ConnectionError as e:
        print("{}[X] Error : Failed to establish a connection, verify that the target exists{}".format(bcolors.RED, bcolors.RESET))
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

    if args.webbeacon or args.cookie :
        content_cookies, content_html = get_content(target.geturl())

    if args.full or (not args.cookie and not args.webbeacon and not args.crypto):
        content_cookies, content_html = get_content(target.geturl())
        result = full(content_cookies, content_html, target.netloc)
    else:
        if args.webbeacon:
            result_webbeacon = webbeacon(content_html)
            result.update(json.loads(result_webbeacon))
        if args.cookie:
            result_cookie = cookie(content_cookies, target.netloc)
            result.update(json.loads(result_cookie))
        if args.crypto:
            result_crypto = crypto(target.netloc)
            #result_crypto = '{ "security_transmission":{ "hostname":"foxnews.com", "grade":"B", "note":44, "protocol":{ "TLSv1":"YES", "TLSv1_1":"YES", "TLSv1_2":"YES", "SSLv2":"NO", "SSLv3":"YES", "TLSv1_3":"NO", "score":"8" }, "key":{ "score":"1", "size":2048, "type":"RSA" }, "cipher":{ "TLSv1":[ "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" ], "TLSv1_1":[ "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" ], "TLSv1_2":[ "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" ] }, "certificate":{ "score":null, "type":"NOOOO-validation", "not_before":"2019-05-16 00:00:00", "not_after":"2020-06-14 12:00:00" } } }'
            result.update(json.loads(result_crypto))

    if args.report:
        if result is None:
            print("{}[X] Error : No result available{}".format(bcolors.RED, bcolors.RESET))
        else:
            generate_report(target.netloc, name, json.dumps(result))

    if args.json:
        print("{}[-] Generate the JSON{}".format(bcolors.RESET, bcolors.RESET))
        if result is None:
            print("{}[X] Error : No result available{}".format(bcolors.RED, bcolors.RESET))
        else:
            folder_target = "reports"
            recording_target = folder_target+"/gdpranalyzer_"+name+"_"+target.netloc+".pdf"
            with open(recording_target, 'w') as outfile:
                json.dump(result, outfile)
            print("{}[-] JSON generated, it is stored in {}{}".format(bcolors.GREEN, recording_target, bcolors.RESET))
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
        print('\033[93m[!] Make sure you have Python 3.7+ installed, quitting.\033[0m')
        sys.exit(1)

    start()
