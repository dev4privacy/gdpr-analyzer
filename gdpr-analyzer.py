#!/usr/bin/env python3

from platform import python_version
import sys
import argparse
import json
from modules.crypto.crypto import TransmissionSecurity
from modules.report.generate_report import generate_report
from modules.web_beacon import find_beacon, json_parser

def cookie(target):
    result = []
    return result

def webbeacon(target):
    #beacon_score, beacon_info = find_beacon(target)
    #result = json_parser(beacon_score, beacon_info)
    return result

def crypto(target):
    crypto = TransmissionSecurity(target)
    crypto.evaluate()
    return crypto.json_parser()

def full(target):
    result_cookie = None
    result_webbeacon = None
    result_crypto = None
    full_result = []

    result_cookie = cookie(target)
    result_webbeacon = webbeacon(target)
    result_crypto = crypto(target)

    full_result = json.loads(result_cookie)
    full_result.update(json.loads(result_webbeacon))
    full_result.update(json.loads(result_crypto))
    return json.dumps(full_result, indent=4)

def start():
    parser = argparse.ArgumentParser(description='Description')

    parser.add_argument('url', help='Target URL')
    parser.add_argument('name', help='Name')
    parser.add_argument('-f', '--full', help='Get Full Analysis, Test All Available Options', action='store_true')
    parser.add_argument('-c', '--cookie', help='lorem ipsum', action='store_true')
    parser.add_argument('-w', '--webbeacon', help='Check for the presence of web beacon', action='store_true')
    parser.add_argument('-t', '--crypto', help='Evaluate the transmision security', action='store_true')
    parser.add_argument('-r', '--report', help='lorem ipsum', action='store_true')
    parser.add_argument('-j', '--json', help='lorem ipsum', action='store_true')

    args = parser.parse_args()
    target = args.url
    name = args.name
    result = None

    if args.full or (not args.cookie and not args.webbeacon and not args.crypto):
        result = full(target)
    else:
        if args.crypto:
            result = crypto(target)

    if args.report:
        if result is None:
            print("no result available")
        else:
            print(result)
            generate_report(target, name, result)

    if args.json:
        if result is None:
            print("no result available")
        else:
            file_name = "gdpr_analyser-" + target + ".json"
            with open(file_name, 'w') as outfile:
                json.dump(result, outfile)

def entry_point():
    try:
        start()
    except KeyboardInterrupt:
        print('\n\n\033[93m[!] ctrl+c detected from user, quitting.\n\n \033[0m')
    except Exception as error_entry_point:
        print(error_entry_point)

if __name__ == '__main__':
    if python_version()[0:3] < '3.5':
        print('\033[93m[!] Make sure you have Python 3.7+ installed, quitting.\033[0m')
        sys.exit(1)

    entry_point()
