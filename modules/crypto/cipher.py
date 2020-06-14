#!/usr/bin/env python3.7
# coding: utf-8

CIPHER_MODE_LIST = ["CBC", "GCM", "CCM", "EDE"]
MAC_TYPE_LIST = ["SHA", "SHA256", "SHA384", "MD5", "POLY1305", "IMIT"]


def __parse_cipher_suite_name(charac):  # TODO function to verify / compare with old one
    """
    Parse the cipher suite string
    """
    # https://ciphersuite.info
    # https://cryptcheck.fr

    # Define key exchange and authentication protocols
    key_exch_protocol = charac["kex_algorithm"]
    auth_protocol = charac["auth_algorithm"].replace("SHA ", "")  # TODO keep or rm SHA?

    if auth_protocol == "anon":
        auth_protocol = ""

    # TODO verify theory
    if key_exch_protocol == "SRP":
        if auth_protocol == "DSS":
            key_exch_protocol = "DSS"
        else:  # auth_protool == "RSA" or == "SHA"
            key_exch_protocol = "RSA"
            auth_protocol = "RSA"

    # print(key_exch_protocol, auth_protocol)

    # Get cipher info
    cipher_info = charac["enc_algorithm"].split(" ")

    # Determine cipher type
    cipher_type = cipher_info[0]

    # TODO : check what is after this
    # Determine cipher key size or mode
    cipher_key_size = None
    cipher_mode = None

    if cipher_info[1].isdigit():
        cipher_key_size = cipher_info[1]
    elif cipher_info[1] in CIPHER_MODE_LIST:
        cipher_mode = cipher_info[1]

    if cipher_type == "CHACHA20":
        cipher_key_size = "256"
        cipher_mode = "AEAD"
    elif cipher_type == "3DES":
        cipher_key_size = "112"
    elif cipher_type == "DES":
        cipher_key_size = "56"
    elif cipher_type == "SEED":
        cipher_key_size = "128"
    elif cipher_type == "IDEA":
        cipher_key_size = "128"
    elif cipher_type == "RC4":
        cipher_mode = ""
    elif cipher_type == "NULL":
        cipher_type = ""
        cipher_key_size = ""
        cipher_mode = ""
    elif cipher_type == "28147":
        cipher_type = "GOST28147"
        cipher_key_size = "256"
        cipher_mode = ""

    # Determine cipher mode
    if cipher_mode is None:
        if cipher_info[2] in CIPHER_MODE_LIST:
            cipher_mode = cipher_info[2]

    # Determine MAC type and size
    mac_type = charac["hash_algorithm"]
    mac_size = None

    if mac_type in MAC_TYPE_LIST:
        if mac_type == "POLY1305":
            mac_size = "128"
        elif mac_type == "MD5":
            mac_size = "128"
        elif mac_type == "IMIT":  # TODO not in json, why here?
            mac_type = "IMIT_GOST28147"
            mac_size = ""
        elif mac_type == "GOSTR3411":  # TODO not in json, why here?
            mac_type = "HMAC_GOSTR3411"
            mac_size = ""
        elif "SHA" in mac_type:
            if mac_type == "SHA":
                mac_type = "SHA1"
                mac_size = "160"
            else:
                mac_size = mac_type[3:]

    if mac_type is None:
        mac_type = ""
    if mac_size is None:
        mac_size = ""

    security = charac['security']

    return auth_protocol, key_exch_protocol, cipher_type, cipher_key_size, cipher_mode, mac_type, mac_size, security


def json_parser(ciphersuite):
    """
    Format the cipher suite informations in json
    """
    cipher_suite_json = {}
    result = {}

    cipher_suite_json["auth_protocol"] = ciphersuite[1]
    cipher_suite_json["key_exch_protocol"] = ciphersuite[2]

    cipher_suite_json["cipher_type"] = ciphersuite[3]
    cipher_suite_json["cipher_key_size"] = ciphersuite[4]
    cipher_suite_json["cipher_mode"] = ciphersuite[5]
    cipher_suite_json["mac_type"] = ciphersuite[6]
    cipher_suite_json["mac_size"] = ciphersuite[7]
    cipher_suite_json["security"] = ciphersuite[8]

    result[ciphersuite[0]] = cipher_suite_json

    return result
