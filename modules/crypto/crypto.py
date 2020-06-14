#!/usr/bin/env python3.7
# coding: utf-8

from datetime import datetime
import json
import configparser
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
import ssl
import socket
import os

from modules.crypto import cipher

config = configparser.ConfigParser()
config.read(os.path.dirname(__file__) + '/config.ini')  # TODO make like Benoît


# config = configparser.ConfigParser()
# config.optionxform = lambda option: option
# config.read('config.ini')


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


def __load_cert(hostname, port_number):  # TODO check this function
    """Recovery the website certificate and its public key"""

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    with socket.create_connection((hostname, port_number)) as sock:
        with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
            pem_data = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(True))

    cert_openssl = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data.encode())
    certificate = cert_openssl.to_cryptography()
    pub_key = certificate.public_key()

    return cert_openssl, pub_key, certificate  # TODO: return cert_openssl useless ?


def __key_data(cert_openssl, pub_key):
    """ Recovery information about the certificate key, key size and signature algorithm."""
    key_size = pub_key.key_size
    sign_algo = cert_openssl.get_signature_algorithm()
    issued_to = cert_openssl.get_subject().CN
    issued_by = cert_openssl.get_issuer().CN

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = "RSA"
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_type = "DSA"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = "EC"
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        key_type = "ED25519"
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        key_type = "ED448"
    else:  # TODO usefull?
        key_type = None

    print("{}{}Key type:{} {}".format(Bcolors.UNDERLINE, Bcolors.BOLD, Bcolors.RESET, key_type))
    print("{}{}Key size:{} {}".format(Bcolors.UNDERLINE, Bcolors.BOLD, Bcolors.RESET, key_size))
    print("{}{}Issued to:{} {}".format(Bcolors.UNDERLINE, Bcolors.BOLD, Bcolors.RESET, issued_to))
    print("{}{}Issued by:{} {}".format(Bcolors.UNDERLINE, Bcolors.BOLD, Bcolors.RESET, issued_by))

    return key_size, sign_algo, issued_to, issued_by, key_type


def __verify(certificate):
    """Verify if certificate is not expired"""

    if certificate.not_valid_after < datetime.today():
        has_expired = True
    else:
        has_expired = False

    return has_expired


def __policie(certificate):  # TODO: check this function
    """Get the type of certificate"""

    strings = ("Extended Validation", "Extended Validated", "EV SSL", "EV CA")
    oid = ["2.16.840.1.114028.10.1.2", "2.16.840.1.114412.1.3.0.2", "2.16.840.1.114412.2.1", "2.16.578.1.26.1.3.3",
           "1.3.6.1.4.1.17326.10.14.2.1.2", "1.3.6.1.4.1.17326.10.8.12.1.2", "1.3.6.1.4.1.13177.10.1.3.10"]

    if any(x in certificate.signature_algorithm_oid.dotted_string for x in oid):
        policie = "extended-validation"
    elif any(x in str(certificate.issuer) for x in strings):
        policie = "extended-validation"
    else:
        policie = "UNKNOW"

    print("{}{}Policie:{} {}".format(Bcolors.UNDERLINE, Bcolors.BOLD, Bcolors.RESET, policie))

    return policie


def __protocol_data(hostname, port):  # TODO: check this function
    """Get all available protocols for connection with the server and all applicable
    ciphersuites for those available
    """
    protocol_enabled = {}
    cipher_available = {}

    print("{}{}{}Protocol and cipher suite available:{}".format(Bcolors.RESET, Bcolors.UNDERLINE, Bcolors.BOLD,
                                                                Bcolors.RESET))

    '''
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    context.options |= ssl.OP_NO_TLSv1_2
    if __protocol_is_enabled(context, protocol):
        protocol_enabled[protocol] = "YES"
        cipher_available[protocol] = __enum_cipher(context)
    else:
        protocol_enabled[protocol] = "NO"

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    context.options |= ssl.OP_NO_TLSv1_2
    if __protocol_is_enabled(context, protocol):
        protocol_enabled[protocol] = "YES"
        cipher_available[protocol] = __enum_cipher(context)
    else:
        protocol_enabled[protocol] = "NO"
    '''

    protocol = "TLSv1"
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    if __protocol_is_enabled(hostname, port, context, protocol):
        protocol_enabled[protocol] = "YES"
        cipher_available[protocol] = __enum_cipher(hostname, port, context, protocol)
    else:
        protocol_enabled[protocol] = "NO"

    protocol = "TLSv1_1"
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    if __protocol_is_enabled(hostname, port, context, protocol):
        protocol_enabled[protocol] = "YES"
        cipher_available[protocol] = __enum_cipher(hostname, port, context, protocol)
    else:
        protocol_enabled[protocol] = "NO"

    protocol = "TLSv1_2"
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    if __protocol_is_enabled(hostname, port, context, protocol):
        protocol_enabled[protocol] = "YES"
        cipher_available[protocol] = __enum_cipher(hostname, port, context, protocol)
    else:
        protocol_enabled[protocol] = "NO"

    protocol = "TLSv1_3"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
    if __protocol_is_enabled(hostname, port, context, protocol):
        protocol_enabled[protocol] = "YES"
        cipher_available[protocol] = __enum_cipher(hostname, port, context, protocol)
    else:
        protocol_enabled[protocol] = "NO"

    protocol_enabled["SSLv2"] = "UNKNOW"
    protocol_enabled["SSLv3"] = "UNKNOW"

    return protocol_enabled, cipher_available


def __protocol_is_enabled(hostname, port_number, context, protocol):  # TODO check this function
    """Return whether the connection with the server via the protocol provided
    in parameter is available.
    Keyword arguments:
    context -- ssl.SSLContex of the connection
    protocol -- protocol tested
    """

    # try:
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port_number)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            ssock.do_handshake()

            if str(ssock.version()).replace(".", "_") != protocol:
                return False
            return True
    # except:  # TODO type of exception ? FOR TLSv3? but why?
    #    return False


def __enum_cipher(hostname, port_number, context, protocol):
    """Returns the list of encryption suites available on the server for the protocol
    provided in parameter.
    Keyword arguments:
    context -- ssl.SSLContex of the connection
    protocol -- protocol tested
    """

    print("{}{}\t {}: {}".format(Bcolors.RESET, Bcolors.BOLD, protocol, Bcolors.RESET))
    cipher_enabled = []

    # TODO https://ciphersuite.info/api/cs/ [make cron using API?]
    with open(os.path.dirname(__file__) + '/cipher_suite_tls.json') as json_file:
        ciphersuites_json = json.load(json_file)

    for ciphersuite in ciphersuites_json['ciphersuites']:
        for ciphersuite_name, ciphersuite_charac in ciphersuite.items():
            try:
                # TODO they don't all have openssl_name / why? / Is this which prevent the connection?
                context.set_ciphers(ciphersuite_charac["openssl_name"])

                with socket.create_connection((hostname, port_number)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        ssock.do_handshake()

                        # TODO clean POO here
                        auth_protocol, key_exch_protocol, cipher_type, cipher_key_size, cipher_mode, mac_type, \
                        mac_size, security = cipher.__parse_cipher_suite_name(ciphersuite_charac)
                        cipher_suite = (
                        ciphersuite_name, auth_protocol, key_exch_protocol, cipher_type, cipher_key_size, cipher_mode,
                        mac_type, mac_size, security)

                        cipher_enabled.append(cipher_suite)

                        print("{}\t\t{}{}".format(Bcolors.RESET, ciphersuite_name, Bcolors.RESET))

            except Exception as e:  # if handshake not work because ssock
                pass
    return cipher_enabled


#    for i in data['ciphersuites']:
#        for key, value in i.items():
#            try:
#                context.set_ciphers(value["openssl_name"])

#                with socket.create_connection((hostname, port_number)) as sock:
#                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                        ssock.do_handshake()

#                cipher_suite = CipherSuite.CipherSuite(key, value["security"])
#                cipher_enabled.append(cipher_suite)
#                print("{}\t\t{}{}".format(Bcolors.RESET, key, Bcolors.RESET))

#            except Exception as e:
#                pass
#    return cipher_enabled

def __protocol_score(protocol_point, protocol_enabled):
    """calculate the score of protocol"""
    # for protocol, point in protocol_point.items():
    #    if protocol_enabled[protocol] == "YES":  # and self.weakest_protocol is None:  # TODO
    #        weakest_protocol = protocol
    #        protocol_score = int(protocol_point[weakest_protocol])

    # TODO: clean strings / scroll list?
    if protocol_enabled["SSLv2"] == "YES":
        weakest_protocol = "SSLv2"
        protocol_score = int(protocol_point[weakest_protocol])
    elif protocol_enabled["SSLv3"] == "YES":
        weakest_protocol = "SSLv3"
        protocol_score = int(protocol_point[weakest_protocol])
    elif protocol_enabled["TLSv1"] == "YES":
        weakest_protocol = "TLSv1"
        protocol_score = int(protocol_point[weakest_protocol])
    elif protocol_enabled["TLSv1_1"] == "YES":
        weakest_protocol = "TLSv1_1"
        protocol_score = int(protocol_point[weakest_protocol])
    elif protocol_enabled["TLSv1_2"] == "YES":
        weakest_protocol = "TLSv1_2"
        protocol_score = int(protocol_point[weakest_protocol])
    else:  # protocol_enabled["TLSv1_3"] == "YES":
        weakest_protocol = "TLSv1_3"
        protocol_score = int(protocol_point[weakest_protocol])

    return protocol_score, weakest_protocol


def __key_score(key_type, key_point, key_point_ec, key_size):
    """calculate the score of certificate key"""

    # TODO: config file point attribution not very clear regarding the if condition
    if key_type == "EC":
        key_score = next((key_point_ec[size] for size in key_point_ec if key_size < int(size)), None)

    else:  # if key_type == "?"
        key_score = next((key_point[size] for size in key_point if key_size < int(size)), None)

    if type(key_score) == str:
        key_score = int(key_score)

    return key_score


def __cipher_score(cipher_available, cipher_point):
    """Calculate the score of cipher suite"""
    cipher_score = 0
    cipher_vulnerability = ""

    for protocol in cipher_available:
        for cipher_suite in cipher_available[protocol]:
            score = int(cipher_point[cipher_suite[8]])
            if score > cipher_score:
                cipher_score = score
                cipher_vulnerability = cipher_suite[8]

    return cipher_score, cipher_vulnerability


def __certificate_score(has_expired, policie, certificate_point):  # TODO function not finished
    """Calculate the score of certificat"""
    if has_expired:
        certificate_score = int(certificate_point["expired"])
    elif policie == "extended-validation":
        certificate_score = int(certificate_point[policie])
    else:  # elif policie == "UNKNOW"
        certificate_score = int(certificate_point["domain-validated"])

    return certificate_score


def __assess_score(coefficient_protocol, coefficient_key, coefficient_cipher, coefficient_certificate, protocol_score,
                   key_score, cipher_score, certificate_score):
    """calculate the overall score of the module"""

    global_score = int(coefficient_protocol) * protocol_score + \
                   int(coefficient_key) * key_score + \
                   int(coefficient_cipher) * cipher_score + \
                   int(coefficient_certificate) * certificate_score

    return global_score


def __assess_rank(bad_rank, weakest_protocol, key_score, cipher_vulnerability, has_expired, global_score,
                  grade):  # TODO function to clean
    """calculate the global rank of the module"""

    global_grade = ""

    for key, value in bad_rank.items():
        if key == "protocol":
            for protocol in value:
                if weakest_protocol == protocol:
                    global_grade = "F"
        elif key == "key_score":
            if key_score >= int(value):
                global_grade = "F"
        elif key == "cipher":
            for vulnerability in value:
                if cipher_vulnerability == vulnerability:
                    global_grade = "F"
        elif has_expired is True:  # TODO: take into consideration other cert possibilities
            global_grade = "F"

    if global_grade != "F":
        print(global_score)
        for letter, score in grade.items():
            if global_score < int(score):
                global_grade = letter
                break

        if global_grade == "":
            global_grade = "F"

    return global_grade


def json_parser(url, global_grade, global_score, protocol_enabled, protocol_score, key_score, key_size, key_type,
                cipher_score, cipher_available, certificate_score, policie, certificate, sign_algo, issued_to,
                issued_by):
    """Parse in json all connection data"""
    security_transmission = {}
    result = {}

    result["hostname"] = url
    result["grade"] = global_grade
    result["note"] = global_score

    result["protocol"] = protocol_enabled
    result["protocol"]["score"] = protocol_score

    result["key"] = {}
    result["key"]["score"] = key_score
    result["key"]["size"] = key_size
    result["key"]["type"] = key_type

    # result["cipher"] = cipher_available
    result["cipher"] = {}
    result["cipher"]["score"] = cipher_score

    for protocol in cipher_available:
        result["cipher"][protocol] = []
        for cipher_suite in cipher_available[protocol]:
            result["cipher"][protocol].append(cipher.json_parser(cipher_suite))

    result["certificate"] = {}
    result["certificate"]["score"] = certificate_score
    result["certificate"]["type"] = policie
    result["certificate"]["not_before"] = certificate.not_valid_before.strftime("%a, %d %b %Y "
                                                                                "%H:%M:%S %Z")
    result["certificate"]["not_after"] = certificate.not_valid_after.strftime("%a, %d %b %Y "
                                                                              "%H:%M:%S %Z")

    result["certificate"]["sign_algo"] = sign_algo.decode("utf-8")
    result["certificate"]["issued_to"] = issued_to
    result["certificate"]["issued_by"] = issued_by

    security_transmission["security_transmission"] = result

    return json.dumps(security_transmission)


def crypto_evaluate(hostname, port):
    # TODO class CertData (useless?)
    # openssl_version = ssl.OPENSSL_VERSION

    # main1
    # TODO class CertData & Tansmission security
    cert_openssl, pub_key, certificate = __load_cert(hostname, port)
    key_size, sign_algo, issued_to, issued_by, key_type = __key_data(cert_openssl, pub_key)
    has_expired = __verify(certificate)
    policie = __policie(certificate)
    protocol_enabled, cipher_available = __protocol_data(hostname, port)

    # TODO problem with TLSv3: display all

    # main2
    # TODO Evaluate (function with score needed defined at beginning)
    protocol_point = config['protocol_point']
    key_point = config['key_point']
    key_point_ec = config['key_point_ec']
    cipher_point = config['cipher_point']
    certificate_point = config['certificate_point']
    bad_rank = config['bad_rank']
    grade = config['grade']

    coefficient = config['coefficient']
    coefficient_protocol = int(config.get('coefficient', 'protocol_point'))
    coefficient_key = int(config.get('coefficient', 'key_point'))
    coefficient_cipher = int(config.get('coefficient', 'cipher_point'))
    coefficient_certificate = int(config.get('coefficient', 'certificate_point'))

    protocol_score, weakest_protocol = __protocol_score(protocol_point, protocol_enabled)
    key_score = __key_score(key_type, key_point, key_point_ec, key_size)
    cipher_score, cipher_vulnerability = __cipher_score(cipher_available, cipher_point)
    certificate_score = __certificate_score(has_expired, policie, certificate_point)
    # score
    global_score = __assess_score(coefficient_protocol, coefficient_key, coefficient_cipher, coefficient_certificate,
                                  protocol_score, key_score, cipher_score, certificate_score)

    rank = __assess_rank(bad_rank, weakest_protocol, key_score, cipher_vulnerability, has_expired, global_score, grade)

    crypto_result = json_parser(hostname, rank, global_score, protocol_enabled, protocol_score, key_score, key_size,
                                key_type, cipher_score, cipher_available, certificate_score, policie, certificate,
                                sign_algo, issued_to, issued_by)

    return crypto_result
