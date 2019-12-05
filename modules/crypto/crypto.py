import json
import configparser
import re
import time
from datetime import datetime
from urllib import parse
import subprocess
import os


class TransmissionSecurity:
    weakest_protocol = None
    protocol_score = None
    protocol_data = {}

    key_size = None
    key_score = None

    certificate_type = None
    certificate_score = None

    cipher_score = None

    data = None

    protocol_point = None
    key_point = None
    cipher_point = None
    certificate_point = None
    bad_rank = None

    coefficient_protocol = None
    coefficient_key = None
    coefficient_cipher = None
    coefficient_certificate = None

    global_score = None
    global_grade = None

    url = None

    def __init__(self, url): 
        self.url = url

        try:
            config = configparser.ConfigParser()
            config.read(os.path.dirname(__file__) + '/config.ini')
        except configparser.Error:
            return

        self.protocol_point = config['protocol_point']
        self.key_point = config['key_point']
        self.cipher_point = config['cipher_point']
        self.certificate_point = config['certificate_point']
        self.bad_rank = config['bad_rank']
        
        coefficient = config['coefficient']
        self.coefficient_protocol = int(config.get('coefficient', 'protocol_point'))
        self.coefficient_key = int(config.get('coefficient', 'key_point'))
        self.coefficient_cipher =int(config.get('coefficient', 'cipher_point'))
        self.coefficient_certificate = int(config.get('coefficient', 'certificate_point'))

        with open(os.path.dirname(__file__) + "/export1.json") as f:
            self.data = json.load(f)

    def __protocol_score(self):
        for item in self.protocol_point:
            for protocol in self.data["scanResult"][0]["protocols"]:
                if protocol["id"].upper() == item.upper():
                    if "not offered" not in protocol["finding"]:
                        self.protocol_data[item] = "OK"
                    else: 
                        self.protocol_data[item] = "KO"
                    if "not offered" not in protocol["finding"] and self.weakest_protocol is None:
                        self.weakest_protocol = protocol["id"]
                        self.protocol_score = self.protocol_point[self.weakest_protocol]

    def __key_score(self):
        for protocol in self.data["scanResult"][0]["serverDefaults"]:
            if protocol["id"] == "cert_keySize":
                self.key_size = int(re.findall(r'\d+', protocol["finding"])[0])

        for item in self.key_point:
            if int(self.key_size) < int(item):
                self.key_score = self.key_point[item]
                break
    
    def __cipher_score(self):
        self.cipher_score = 0

    def __certificate_score(self):
        for serverDefault in self.data["scanResult"][0]["serverDefaults"]:
            if serverDefault["id"] == "cert_notAfter":
                if time.time() > time.mktime(time.strptime(serverDefault["finding"], "%Y-%m-%d %H:%M")):
                    self.certificate_type = "expired"
                    break
            if serverDefault["id"] == "cert_chain_of_trust":
                if "self signed" in serverDefault["finding"]:
                    self.certificate_type = "self-signed"
                    break
            if serverDefault["id"] == "cert_certificatePolicies_EV":
                if serverDefault["finding"] == "yes":
                    self.certificate_type = "EV"
                    break

            if serverDefault["id"] == "cert_chain_of_trustc":
                certificate_type = re.findall("DV|DOMAIN VALIDATION|EXTENDED VALIDATION|EV", serverDefault["finding"])
        if self.certificate_type is not None :
            self.certificate_score = self.certificate_point[self.certificate_type]

    def __assess_rank(self):
        #protocol point
        for protocol in self.bad_rank["protocol"].split(','):
            if self.weakest_protocol == protocol:
                self.global_grade = 'F'
        
        for certificate in self.bad_rank["certificate"].split(','):
            if self.certificate_type == certificate:
                self.global_grade = 'F'

        #TO DO calculate global grade
        if self.global_grade is None:
            self.global_grade = "B"

    def __assess_score(self):
        self.global_score = int(self.coefficient_protocol) * int(self.protocol_score) + \
                            int(self.coefficient_key) * int(self.key_score) + \
                            int(self.coefficient_cipher) * int(self.cipher_score) + \
                            int(self.coefficient_certificate) * int(self.certificate_score)

    def evaluate(self):
        self.__protocol_score()
        self.__key_score()
        self.__cipher_score()
        self.__certificate_score()

        #score
        self.__assess_score()
        self.__assess_rank()

    def json_parser(self):
        security_transmission = {}
        result = {}

        result["grade"] = self.global_grade
        result["note"] = self.global_score

        result["protocol"] = self.protocol_data
        result["protocol"]["score"] = self.protocol_score

        result["key"] = {}
        result["key"]["score"] = self.key_score
        result["key"]["size"] = self.key_size

        result["cipher"] = {}

        result["certificate"] = {}
        result["certificate"]["score"] = self.certificate_score
        result["certificate"]["type"] = self.certificate_type

        security_transmission["security_transmission"] = result
        return json.dumps(security_transmission)

    def get_weakest_protocol(self):
        return self.weakest_protocol

    def get_protocol_score(self):
        return self.protocol_score
    
    def get_key_size(self):
        return self.key_size
    
    def get_key_score(self):
        return self.key_score

    def get_certificate_type(self):
        return self.certificate_type
    
    def get_certificate_score(self):
        return self.certificate_score
    
    def get_global_score(self):
        return self.global_score

    def get_global_grade(self):
        return self.global_grade
