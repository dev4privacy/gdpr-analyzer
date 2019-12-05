#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
from datetime import date
import json
import os


def generate_report(target, name, result):
    file_loader = FileSystemLoader(os.path.dirname(__file__)+'/templates')
    env = Environment(loader=file_loader)

    tm = env.get_template('template.html')

    resultDict = json.loads(result)
    
    scMod = resultDict['security_transmission']
    #cookiesMod = resultDict['cookies']
    #wbMod = resultDict['webBeacons']

    generated_date = date.today().strftime("%d/%m/%Y")

    output = tm.render(client_name=name, target=target, generated_date=generated_date, cookies="", scMod = scMod, wbMod = "")

    #TODO check if report folder exist
    HTML(string=output).write_pdf("reports/gdpranalyzer-"+target+"-"+name+".pdf", stylesheets=[os.path.dirname(__file__)+"/templates/style.css"])
