#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from datetime import date
import json
import os

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

def generate_report(target, name, result):
    print("{}[-] Generate the report{}".format(bcolors.RESET, bcolors.RESET))

    folder_target = "reports"
    recording_target = folder_target+"/gdpranalyzer_"+name+"_"+target+".pdf"

    try:
        if not os.path.exists(folder_target):
            os.mkdir(folder_target)
    except OSError:
        print("{}Error : The folder '{}' not exist and failed to create{}".format(bcolors.RED, folder_target,bcolors.RESET))

    file_loader = FileSystemLoader(os.path.dirname(__file__)+'/templates')
    env = Environment(loader=file_loader)

    tm = env.get_template('template.html')

    resultDict = json.loads(result)

    if 'security_transmission' in resultDict:
        scMod = resultDict['security_transmission']
    else:
        scMod = {}

    if 'cookies' in resultDict:
        cookiesMod = resultDict['cookies']
    else:
        cookiesMod = {}

    if 'web_beacons' in resultDict:
        wbMod = resultDict['web_beacons']
    else:
        wbMod = {}

    generated_date = date.today().strftime("%d/%m/%Y")

    output = tm.render(client_name=name, target=target, generated_date=generated_date, cookies=cookiesMod, scMod = scMod, wbMod = wbMod)

    HTML(string=output).write_pdf(recording_target, stylesheets=[os.path.dirname(__file__)+"/templates/style.css",os.path.dirname(__file__)+"/templates/bootstrap-grid.min.css"])

    print("{}[-] Report generated, it is stored in {}{}".format(bcolors.GREEN, recording_target, bcolors.RESET))

    return recording_target