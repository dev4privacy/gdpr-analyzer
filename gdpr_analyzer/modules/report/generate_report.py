#!/usr/bin/env python3.7
# coding: utf-8

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from datetime import date
import json
import os


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


def generate_report(name, result, path):
    print("{}[-] Generate the report{}".format(Bcolors.RESET, Bcolors.RESET))

    file_loader = FileSystemLoader(os.path.dirname(__file__)+'/templates')
    env = Environment(loader=file_loader)

    tm = env.get_template('template.html')

    result_dict = json.loads(result)

    if 'security_transmission' in result_dict:
        scMod = result_dict['security_transmission']
    else:
        scMod = {}

    if 'cookies' in result_dict:
        cookiesMod = result_dict['cookies']
    else:
        cookiesMod = {}

    if 'web_beacons' in result_dict:
        wbMod = result_dict['web_beacons']
    else:
        wbMod = {}

    generated_date = date.today().strftime("%d/%m/%Y")

    output = tm.render(client_name=name, grade=result_dict["grade"], target=result_dict["target"],
                       generated_date=generated_date, cookies=cookiesMod, scMod=scMod, wbMod=wbMod)

    HTML(string=output).write_pdf(path, stylesheets=[os.path.dirname(__file__)+"/templates/style.css",
                                                     os.path.dirname(__file__)+"/templates/bootstrap-grid.min.css"])

    print("{}[-] Report generated, it is stored in {}{}".format(Bcolors.GREEN, path, Bcolors.RESET))
