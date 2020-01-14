from enum import Enum

import json

CIPHER_MODE_LIST = ["CBC", "GCM", "CCM", "EDE"]
MAC_TYPE_LIST = ["SHA", "SHA256", "SHA384", "MD5", "POLY1305", "IMIT"]

class CipherSuite:

    def __init__(self, cipher_suite_string):
        print(cipher_suite_string)
        self.name = cipher_suite_string.strip().replace("TLS_","").replace("OLD_", "")
        self.key_exch_protocol = None
        self.auth_protocol = None
        self.cipher_type = None
        self.cipher_key_size = None
        self.cipher_mode = None
        self.mac_type = None
        self.mac_size = None

        self.__parse_cipher_suite_name()


    def __parse_cipher_suite_name(self):
        cipher_suite_fields = self.name.split("WITH")
        cipher_suite_exch_auth_protocol = cipher_suite_fields[0].replace("SHA_","").split("_")
        del cipher_suite_exch_auth_protocol[-1]
        cipher_suite_cipher_mac_protocol = cipher_suite_fields[1].split("_")
        del cipher_suite_cipher_mac_protocol[0]

        #Determine the key exchange protocol
        self.key_exch_protocol = cipher_suite_exch_auth_protocol[0]

        #Determine the authentification protocol
        if len(cipher_suite_exch_auth_protocol) >= 2 and cipher_suite_exch_auth_protocol[1] != "EXPORT" :
            self.auth_protocol = cipher_suite_exch_auth_protocol[1]
        else :
            self.auth_protocol = cipher_suite_exch_auth_protocol[0]

        if self.auth_protocol == "anon" :
            if self.key_exch_protocol == "DH" :
                self.auth_protocol = ""
            elif self.key_exch_protocol == "ECDH" :
                self.auth_protocol = ""

        if self.key_exch_protocol == "SRP" :
            if self.auth_protocol == "DSS":
                self.key_exch_protocol = "DSS"
            else :
                self.auth_protocol = "RSA"
                self.key_exch_protocol = "RSA"

        #Determine the cipher type protocol and key size
        self.cipher_type = cipher_suite_cipher_mac_protocol[0]

        if self.cipher_type == "CHACHA20":
            self.cipher_key_size = "256"
            self.cipher_mode = "AEAD"
        elif self.cipher_type == "3DES" :
            self.cipher_key_size = "112"
        elif self.cipher_type == "DES" :
            self.cipher_key_size = "56"
        elif self.cipher_type == "SEED" :
            self.cipher_key_size = "128"
        elif self.cipher_type == "IDEA" :
            self.cipher_key_size = "128"
        elif self.cipher_type == "RC4" :
            self.cipher_mode = ""
        elif self.cipher_type == "NULL" :
            self.cipher_type = ""
            self.cipher_key_size = ""
            self.cipher_mode = ""
        elif self.cipher_type == "28147" :
            self.cipher_type = "GOST28147"
            self.cipher_key_size = "256"
            self.cipher_mode = ""

        if cipher_suite_cipher_mac_protocol[1].isdigit() :
            self.cipher_key_size = cipher_suite_cipher_mac_protocol[1]
        elif cipher_suite_cipher_mac_protocol[1] in CIPHER_MODE_LIST :
            self.cipher_mode = cipher_suite_cipher_mac_protocol[1]

        #Determine cipher mode

        if self.cipher_mode == None :
            if cipher_suite_cipher_mac_protocol[2] in CIPHER_MODE_LIST :
                self.cipher_mode = cipher_suite_cipher_mac_protocol[2]

        #Determine MAC type and size

        if cipher_suite_cipher_mac_protocol[-1] in MAC_TYPE_LIST :
            self.mac_type = cipher_suite_cipher_mac_protocol[-1]
            if self.mac_type == "POLY1305" :
                self.mac_size = "128"
            elif self.mac_type == "MD5" :
                self.mac_size = "128"
            elif self.mac_type == "IMIT" :
                self.mac_type = "IMIT_GOST28147"
                self.mac_size = ""
            elif self.mac_type == "GOSTR3411" :
                self.mac_type = "HMAC_GOSTR3411"
                self.mac_size = ""
            elif "SHA" in self.mac_type :
                if self.mac_type == "SHA" :
                    self.mac_type = "SHA1"
                    self.mac_size = "160"
                else :
                    self.mac_size = self.mac_type[3:]

        if self.mac_type == None :
            self.mac_type = ""
        if self.mac_size == None :
            self.mac_size = ""


    def json_parser(self) :
        cipher_suite_json = {}
        result = {}
        cipher_suite_json["key_exch_protocol"] = self.key_exch_protocol
        cipher_suite_json["auth_protocol"] = self.auth_protocol
        cipher_suite_json["cipher_type"] = self.cipher_type
        cipher_suite_json["cipher_key_size"] = self.cipher_key_size
        cipher_suite_json["cipher_mode"] = self.cipher_mode
        cipher_suite_json["mac_type"] = self.mac_type
        cipher_suite_json["mac_size"] = self.mac_size

        result[self.name] = cipher_suite_json

        return json.dumps(result)
