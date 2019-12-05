#!/usr/bin/env python3

from platform import python_version
import sys
import argparse
import json

def cookie(target):
    result = ""
    print("cookie")
    return result

def webbeacon(target):
    result = ""
    print("webbeacon")
    return result

def crypto(target):
    result = ""
    print("crypto")
    return result

def report(target, name, result):
    print()

def full(target):
    result_cookie = None
    result_webbeacon = None
    result_crypto = None

    result_cookie = cookie(target)
    result_webbeacon = webbeacon(target)
    result_crypto = crypto(target)

    #return merge all result 
    
def start(): 
    parser = argparse.ArgumentParser(description='Description')

    parser.add_argument('url', help='Target URL')
    parser.add_argument('name', help='Name')
    parser.add_argument('-f', '--full', help='Get Full Analysis, Test All Available Options', action='store_true')
    parser.add_argument('-c', '--cookie', help='lorem ipsum', action='store_true')
    parser.add_argument('-w', '--webbeacon', help='lorem ipsum', action='store_true')
    parser.add_argument('-t', '--crypto', help='Evaluate the transmision security', action='store_true')
    parser.add_argument('-r', '--report', help='lorem ipsum', action='store_true')
    parser.add_argument('-j', '--json', help='lorem ipsum', action='store_true')
    
    args = parser.parse_args()
    target = args.url
    name = args.name
    result = None

    '''
    # gerer la fusion de plusieurs resultat pour un export (rapport ou json)
    if args.cookie : 
        result = cookie(target)
    if args.webbeacon : 
        result = webbeacon(target)  
    if args.crypto : 
        result += crypto(target)  
    '''

    if args.full or (not args.cookie and not args.webbeacon and not args.crypto):
        result = full(target)

    if args.report:
        if result is None:
            print("no result available")
        else:
            report(target, name, result)
    
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
    if python_version()[0:3] < '3.7':
        print('\033[93m[!] Make sure you have Python 3.7+ installed, quitting.\033[0m')
        sys.exit(1)

    entry_point()