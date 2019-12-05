#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from datetime import date
import json


def generate_report(target, name, result):
    file_loader = FileSystemLoader('templates')
    env = Environment(loader=file_loader)

    tm = env.get_template('template.html')

    resultDict = json.load(result)

    scMod = resultDict['security_transmission']
    cookiesMod = resultDict['cookies']
    wbMod = resultDict['webBeacons']

    generated_date = date.today().strftime("%d/%m/%Y")

    output = tm.render(client_name=name, target=target, generated_date=generated_date, cookies=cookiesMod, scMod = scMod, wbMod = wbMod)

    HTML(string=output).write_pdf("gdpranalyzer-"+target+"-"+name+".pdf", stylesheets=["templates/style.css"])
