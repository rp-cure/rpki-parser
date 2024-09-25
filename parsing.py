'''
This file provides a wrapper to asn1crypto to easily parse RPKI objects.
'''

from asn1crypto.cms import ContentInfo, Certificate
from templates import RouteOriginAttestation
from templates import Manifest
from templates import CertificateRevocationList

import base64
from enum import Enum


class ObjectType(Enum):
    CERTIFICATE = 1
    ROA = 2
    MFT = 3
    CRL = 4


'''
Parse RPKI object in binary (DER-encoded) format.
Returns the parsed object and a dictionary with the object content.
'''


def parse_object_der(data, object_type: ObjectType):
    if object_type == ObjectType.CERTIFICATE:
        c = Certificate()
        parsed = c.load(data)
        native = parsed.native
        return parsed, native

    elif object_type == ObjectType.CRL:
        c = CertificateRevocationList()
        parsed = c.load(data)
        native = parsed.native
        return parsed, native

    elif object_type == ObjectType.ROA or object_type == ObjectType.MFT:
        contentInfo = ContentInfo()
        parsed = contentInfo.load(data)

        native = parsed.native

        content = native["content"]

        # The content of ROA and MFT is contained inside the encapsulatedContent field of the SignedData
        #  which needs to be decoded separately
        enc_content = content['encap_content_info']

        con_type = enc_content["content_type"]

        if con_type == '1.2.840.113549.1.9.16.1.24':
            template = RouteOriginAttestation()
        elif con_type == '1.2.840.113549.1.9.16.1.26':
            template = Manifest()
        else:
            assert False

        object = template.load(enc_content["content"])

        # Replace the binary (unparsed) content with parsed content
        enc_content["content"] = [object, enc_content["content"]]

        return parsed, native


def print_list(obj, intent=0):
    for el in obj:
        if str(type(el)) == "<class 'collections.OrderedDict'>":
            print_dict(el, intent+2)
        elif str(type(el)) == "<class 'list'>":
            print_list(el, intent + 2)
        elif "RouteOriginAttestation" in str(type(el)) or "Manifest" in str(type(el)):
            print_dict(el.native, intent+2)
        else:
            if str(type(el)) == "<class 'tuple'>":
                val = hex(int("".join(str(ele) for ele in el), 2))
            elif str(type(el)) == "<class 'bytes'>":
                val = el.hex()
            else:
                val = el
            print(" "*intent + str(val))


def print_dict(obj, intent=0):
    if str(type(obj)) == "<class 'list'>":
        it = obj
    else:
        it = [obj]
    for v in it:
        for key in v:
            if str(type(v[key])) == "<class 'collections.OrderedDict'>":
                print_dict(v[key], intent + 2)
            elif str(type(v[key])) == "<class 'list'>":
                print_list(v[key], intent + 2)
            else:
                if str(type(v[key])) == "<class 'tuple'>":
                    val = hex(int("".join(str(ele) for ele in v[key]), 2))
                elif str(type(v[key])) == "<class 'bytes'>":
                    val = v[key].hex()
                else:
                    val = v[key]
                print(" "*intent + str(key) + ": " + str(val))


'''
Parse object in base64 encoded format.
Returns the parsed object and a dictionary with the object content.
'''


def parse_object_base64(data_b64, object_type: ObjectType):
    data = base64.decodebytes(data_b64)
    return (data, object_type)


filename = "/home/nvogel/Downloads/crl-noext(1)"
filename = "/home/nvogel/Downloads/PQbVL1tWkVROU8PkFU-IprR49Xo.roa"

with open(filename, 'rb') as f:
    data = f.read()

p, a = parse_object_der(data, ObjectType.ROA)

object_content = a["content"]["encap_content_info"]["content"][0].native

c = object_content["as-id"]
print("Fields of Object:", object_content)
print("ASID:", c)
print_dict(object_content)
