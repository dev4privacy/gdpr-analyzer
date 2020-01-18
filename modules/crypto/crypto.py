from datetime import datetime
import json
import configparser
from OpenSSL import crypto

import cryptography
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
import ssl
import os

from modules.crypto import const
from modules.crypto import CipherSuite

from ssl import PROTOCOL_TLSv1_2

config = configparser.ConfigParser()
config.optionxform = lambda option: option
config.read('config.ini')
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

class CertData:

    def __init__(self, url):
        self.openssl_version = ssl.OPENSSL_VERSION
        self.protocol_enabled = {}

        self.hostname = url
        self.port_number = 443

        self.key_size = None
        self.key_type = None

        self.policie = None

        self.cert = None
        self.certOpenSSL = None
        self.certCrypto = None
        self.pubKey = None

        self.sign_algo = None
        self.issued_to = None
        self.issued_by = None

        self.__load_cert()
        self.__key_data()
        self.__protocol_data()
        self.__policie()
        self.__verify()


    def __load_cert(self):
        conn = ssl.create_connection((self.hostname, self.port_number))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        sock = context.wrap_socket(conn, server_hostname=self.hostname)

        self.pem_data = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        self.certOpenSSL = crypto.load_certificate(crypto.FILETYPE_PEM, self.pem_data)
        
        self.certificate = self.certOpenSSL.to_cryptography()

        self.pubKey = self.certificate.public_key()

        

    def __key_data(self):
        self.key_size = self.pubKey.key_size
        self.sign_algo = self.certOpenSSL.get_signature_algorithm()
        self.issued_to = self.certOpenSSL.get_subject().CN
        self.issued_by = self.certOpenSSL.get_issuer().CN

        if isinstance(self.pubKey, asymmetric.rsa.RSAPublicKey):
            self.key_type = "RSA"
        elif isinstance(self.pubKey, asymmetric.dsa.DSAPublicKey):
            self.key_type = "DSA"
        elif isinstance(self.pubKey, asymmetric.ec.EllipticCurvePublicKey):
            self.key_type = "EC"
        elif isinstance(self.pubKey, asymmetric.ed25519.Ed25519PublicKey):
            self.key_type = "ED25519"
        elif isinstance(self.pubKey, asymmetric.ed448.Ed448PublicKey):
            self.key_type = "ED448"

        

    def __procotol_is_enable(self, context, protocol):
        try:
            '''
            conn = ssl.create_connection((self.hostname, self.port_number))
            sock = context.wrap_socket(conn, server_hostname=self.hostname)
            sock.do_handshake()
            '''
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = ssl.create_connection((self.hostname, self.port_number))
            sock = context.wrap_socket(conn, server_hostname=self.hostname)
            sock.do_handshake()
            if str(sock.version()).replace(".", "_") != protocol:
                return False
            return True
        except:
            return False
    
    def __enum_cipher(self, context, protocol):
        print("{}{}\t {}: {}".format(bcolors.RESET, bcolors.BOLD, protocol, bcolors.RESET))
        cipher_enable = []

        if protocol == "TLSv1_3":
            with open(os.path.dirname(__file__) + '/cipher_suite_tls_v13.json') as json_file:
                data = json.load(json_file)
        elif protocol == "TLSv1_2":
            with open(os.path.dirname(__file__) + '/cipher_suite_tls_v12.json') as json_file:
                data = json.load(json_file)
        elif protocol == "TLSv1_1":
            with open(os.path.dirname(__file__) + '/cipher_suite_tls_v11.json') as json_file:
                data = json.load(json_file)
        elif protocol == "TLSv1":
            with open(os.path.dirname(__file__) + '/cipher_suite_tls_v10.json') as json_file:
                data = json.load(json_file)

        for i in data['ciphersuites'] :
            for key, value in i.items() :
                try:
                    conn = ssl.create_connection((self.hostname, self.port_number))
                    context.set_ciphers(value["openssl_name"])
                    sock = context.wrap_socket(conn, server_hostname=self.hostname)
                    sock.do_handshake()
                    cipher_suite = CipherSuite.CipherSuite(key, value["security"])
                    cipher_enable.append(cipher_suite)
                    print("{}\t\t{}{}".format(bcolors.RESET, key, bcolors.RESET))
                except Exception as e: 
                    pass
        '''
        for key, value in cipher_suites.items() :
            try:
                conn = ssl.create_connection((self.hostname, self.port_number))
                context.set_ciphers(key)
                sock = context.wrap_socket(conn, server_hostname=self.hostname)
                sock.do_handshake()
                #cipher_suite = CipherSuite.CipherSuite(cipher_suites[key])
                cipher_enable.append(cipher_suite)
            except Exception as e: 
                pass
        '''

        return cipher_enable

    def __protocol_data(self):
        print("{}{}{}Available cipher suite : {}".format(bcolors.RESET, bcolors.UNDERLINE, bcolors.BOLD, bcolors.RESET))
        self.cipher_available = {}

        '''
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_NO_TLSv1_2
        if self.__procotol_is_enable(context, protocol):
            self.protocol_enabled[protocol] = "YES"
            self.cipher_available[protocol] = self.__enum_cipher(context)
        else:
            self.protocol_enabled[protocol] = "NO"
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_NO_TLSv1_2
        if self.__procotol_is_enable(context, protocol):
            self.protocol_enabled[protocol] = "YES"
            self.cipher_available[protocol] = self.__enum_cipher(context)
        else:
            self.protocol_enabled[protocol] = "NO"
        '''

        protocol = "TLSv1"
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        if self.__procotol_is_enable(context, protocol):
            self.protocol_enabled[protocol] = "YES"
            self.cipher_available[protocol] = self.__enum_cipher(context, protocol)
        else:
            self.protocol_enabled[protocol] = "NO"
        
        protocol = "TLSv1_1"
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
        if self.__procotol_is_enable(context, protocol):
            self.protocol_enabled[protocol] = "YES"
            self.cipher_available[protocol] = self.__enum_cipher(context, protocol)
        else:
            self.protocol_enabled[protocol] = "NO"

        protocol = "TLSv1_2"
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        if self.__procotol_is_enable(context, protocol):
            self.protocol_enabled[protocol] = "YES"
            self.cipher_available[protocol] = self.__enum_cipher(context, protocol)
        else:
            self.protocol_enabled[protocol] = "NO"
            
        protocol = "TLSv1_3"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
        if self.__procotol_is_enable(context, protocol):
            self.protocol_enabled[protocol] = "YES"
            self.cipher_available[protocol] = self.__enum_cipher(context, protocol)
        else:
            self.protocol_enabled[protocol] = "NO"    

        self.protocol_enabled["SSLv2"] = "UNKNOW"      
        self.protocol_enabled["SSLv3"] = "UNKNOW"      
    
    def __policie(self):
        strings = ("Extended Validation","Extended Validated","EV SSL","EV CA")
        oid= ["2.16.840.1.114028.10.1.2", "2.16.840.1.114412.1.3.0.2","2.16.840.1.114412.2.1" ,
            "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.17326.10.14.2.1.2", "1.3.6.1.4.1.17326.10.8.12.1.2", 
            "1.3.6.1.4.1.13177.10.1.3.10"]

        if any(x in self.certificate.signature_algorithm_oid.dotted_string for x in oid):
            self.policie = "extended-validation"
        elif any(x in str(self.certificate.issuer) for x in strings):
            self.policie = "extended-validation"
        else:
            self.policie = "UNKNOW"

    def __verify(self):
        if self.certificate.not_valid_after < datetime.today():
            self.has_expired = True
        else:
            self.has_expired = False

class TransmissionSecurity:
    def __init__(self, url): 
        self.url = url

        self.weakest_protocol = None
        self.cipher_vulnerability = None

        self.key_score = None
        self.protocol_score = None
        self.certificate_score = None
        self.cipher_score = None

        self.global_score = None
        self.global_grade = None

        self.cert_data = CertData(url)
        self.__load_config()
    
    def __load_config(self):

        try:
            config = configparser.ConfigParser()
            config.optionxform=str
            config.read(os.path.dirname(__file__) + '/config.ini')
        except configparser.Error:
            return

        self.protocol_point = config['protocol_point']
        self.key_point = config['key_point']
        self.key_point_ec = config['key_point_ec']
        self.cipher_point = config['cipher_point']
        self.certificate_point = config['certificate_point']
        self.bad_rank = config['bad_rank']
        self.grade = config['grade']
        
        coefficient = config['coefficient']
        self.coefficient_protocol = int(config.get('coefficient', 'protocol_point'))
        self.coefficient_key = int(config.get('coefficient', 'key_point'))
        self.coefficient_cipher =int(config.get('coefficient', 'cipher_point'))
        self.coefficient_certificate = int(config.get('coefficient', 'certificate_point'))

    def __key_score(self):
        if self.cert_data.key_type == "EC":
            for item in self.key_point_ec:
                if int(self.cert_data.key_size < int(item)):
                    self.key_score = int(self.key_point_ec[item])
                    break
        else:
            for item in self.key_point:
                if int(self.cert_data.key_size < int(item)):
                    self.key_score = int(self.key_point[item])
                    break
        
    def __protocol_score(self):
        for key, value in self.protocol_point.items():
            if self.cert_data.protocol_enabled[key] == "YES" and self.weakest_protocol is None:
                self.weakest_protocol = key
                self.protocol_score = int(self.protocol_point[self.weakest_protocol])

    def __cipher_score(self):
        for protocol in self.cert_data.cipher_available :
            for cipher_suite in self.cert_data.cipher_available[protocol]:
                score = int(self.cipher_point[cipher_suite.security])
                if self.cipher_score is None or score > self.cipher_score: 
                    self.cipher_score = score
                    self.cipher_vulnerability = cipher_suite.security
    
    def __certificate_score(self):
        if self.cert_data.has_expired : 
            self.certificate_score = int(self.certificate_point["expired"])
            self.global_grade = "F"
        elif self.cert_data.policie == "extended-validation":
            self.certificate_score = int(self.certificate_point[self.cert_data.policie])
        elif self.cert_data.policie == "UNKNOW":
            self.certificate_score = int(self.certificate_point["domain-validated"])


    def __assess_rank(self):
        #TO DO calculate global grade

        for key, value in self.bad_rank.items():
            if key == "protocol":
                for i in value:
                    if self.weakest_protocol == i:
                        self.global_grade = "F"
                        break
            elif key == "key_score":
                if self.key_score <= int(value):
                    self.global_grade = "F"
            elif key == "cipher":
                for i in value:
                    if self.cipher_vulnerability == i:
                        self.global_grade = "F"
                        break

        if self.global_grade is None:
            for key, value in self.grade.items():
                if self.global_score < int(value):
                    self.global_grade = key
                    break
            if self.global_grade is None:
                self.global_grade = "F"

    def __assess_score(self):
        self.global_score = None

        self.global_score = int(self.coefficient_protocol) * self.protocol_score + \
                            int(self.coefficient_key) * self.key_score + \
                            int(self.coefficient_cipher) * self.cipher_score + \
                            int(self.coefficient_certificate) * self.certificate_score


    def evaluate(self):
        self.__protocol_score()
        self.__key_score()
        self.__cipher_score()
        self.__certificate_score()

        #score
        self.__assess_score()
        self.__assess_rank()
        print("{}{}{}Score :{} {}".format(bcolors.RESET, bcolors.UNDERLINE, bcolors.BOLD, bcolors.RESET, self.global_score))
        print("{}{}{}Grade :{} {}".format(bcolors.RESET, bcolors.UNDERLINE, bcolors.BOLD, bcolors.RESET, self.global_grade))

    def json_parser(self):
        security_transmission = {}
        result = {}
        result["hostname"] = self.url
        result["grade"] = self.global_grade
        result["note"] = self.global_score

        result["protocol"] = self.cert_data.protocol_enabled
        result["protocol"]["score"] = self.protocol_score

        result["key"] = {}
        result["key"]["score"] = self.key_score
        result["key"]["size"] = self.cert_data.key_size
        result["key"]["type"] = self.cert_data.key_type

        #result["cipher"] = self.cert_data.cipher_available
        result["cipher"] = {}
        result["cipher"]["score"] = self.cipher_score
        for protocol in self.cert_data.cipher_available :
            result["cipher"][protocol] = []
            for cipher_suite in self.cert_data.cipher_available[protocol] :
                result["cipher"][protocol].append(cipher_suite.json_parser())

        result["certificate"] = {}
        result["certificate"]["score"] = self.certificate_score
        result["certificate"]["type"] = self.cert_data.policie
        result["certificate"]["not_before"] = self.cert_data.certificate.not_valid_before.strftime("%a, %d %b %Y %H:%M:%S %Z")
        result["certificate"]["not_after"] = self.cert_data.certificate.not_valid_after.strftime("%a, %d %b %Y %H:%M:%S %Z")

        result["certificate"]["sign_algo"] = self.cert_data.sign_algo.decode("utf-8") 
        result["certificate"]["issued_to"] = self.cert_data.issued_to
        result["certificate"]["issued_by"] = self.cert_data.issued_by

        security_transmission["security_transmission"] = result
        return json.dumps(security_transmission)
