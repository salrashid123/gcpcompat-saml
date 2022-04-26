#!/usr/bin/python


import base64
import datetime
import getopt

import random
import sys
import time
import zlib
from socket import gethostname
from xml.sax.saxutils import escape

import libxml2
import xmlsec
import xml.dom.minidom

debug_flag = False
saml_issuer = "authn.py"
audience=""
key_file = ''
key_pwd = ''
cert_file = None


class SignatureError(Exception):
    pass


def getrandom_samlID():
    return '_' + hex(random.getrandbits(124))[2:-1]


def _generate_response(now, later, username, login_req_id, recipient, audience):
    resp_rand_id = getrandom_samlID()
    rand_id_assert = getrandom_samlID()
    sigtmpl = ''

    sigtmpl = ('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
                '<ds:SignedInfo>'
                '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
                '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />'
                '<ds:Reference URI="#%s">'
                '<ds:Transforms>'
                '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />'
                '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />'
                '</ds:Transforms>'
                '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />'
                '<ds:DigestValue></ds:DigestValue>'
                '</ds:Reference>'
                '</ds:SignedInfo>'
                '<ds:SignatureValue/>'
                '<ds:KeyInfo>'
                '<ds:X509Data>'
                '<ds:X509Certificate></ds:X509Certificate>'
                '</ds:X509Data>'
                '</ds:KeyInfo>'
                '</ds:Signature>') % (resp_rand_id)
    resp = ('<saml2p:Response '
                'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" '
                'ID="%s" InResponseTo="%s" Version="2.0" IssueInstant="%s" >'
                '<saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">%s</saml2:Issuer>'
                '%s'
                '<saml2p:Status  xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
                '<saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
                '</saml2p:Status>'
                '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
                'Version="2.0" ID="%s" IssueInstant="%s">'
                '<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">%s</saml2:Issuer>'
                '<saml2:Subject>'
                '<saml2:NameID  Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml2:NameID>'
                '<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
                '<saml2:SubjectConfirmationData InResponseTo="%s" Recipient="%s" NotOnOrAfter="%s"/>'
                '</saml2:SubjectConfirmation>'
                '</saml2:Subject>'
                '<saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">'
                '<saml2:AudienceRestriction>'
                '<saml2:Audience>%s</saml2:Audience>'
                '</saml2:AudienceRestriction>'
                '</saml2:Conditions>'
                '<saml2:AuthnStatement AuthnInstant="%s" SessionIndex="%s">'
                '<saml2:AuthnContext>'
                '<saml2:AuthnContextClassRef>'
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
                '</saml2:AuthnContextClassRef>'
                '</saml2:AuthnContext>'
                '</saml2:AuthnStatement>'
                '<saml2:AttributeStatement>'
                '<saml2:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
                '<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">group1</saml2:AttributeValue>'
                '<saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">group2</saml2:AttributeValue>'                
                '</saml2:Attribute>'
                '</saml2:AttributeStatement>'
                '</saml2:Assertion>'
                '</saml2p:Response>') % (resp_rand_id, login_req_id, now,
                                        saml_issuer, sigtmpl, rand_id_assert, now,
                                        saml_issuer, username,
                                        login_req_id, recipient, later,
                                        now, later, audience,
                                        now, rand_id_assert)


    resp = '<!DOCTYPE saml2p:Response [<!ATTLIST saml2p:Response ID ID #IMPLIED>]>' + resp
    resp = _signXML(resp)
    return resp


def _signXML(xml):
    dsigctx = None
    doc = None
    try:
        # initialization
        libxml2.initParser()
        libxml2.substituteEntitiesDefault(1)
        if xmlsec.init() < 0:
            raise SignatureError('xmlsec init failed')
        if xmlsec.checkVersion() != 1:
            raise SignatureError('incompatible xmlsec library version %s' %
                                 str(xmlsec.checkVersion()))
        if xmlsec.cryptoAppInit(None) < 0:
            raise SignatureError('crypto initialization failed')
        if xmlsec.cryptoInit() < 0:
            raise SignatureError('xmlsec-crypto initialization failed')

        # load the input
        doc = libxml2.parseDoc(xml)
        if not doc or not doc.getRootElement():
            raise SignatureError('error parsing input xml')
        node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature,
                               xmlsec.DSigNs)
        if not node:
            raise SignatureError("couldn't find root node")

        dsigctx = xmlsec.DSigCtx()

        key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                      key_pwd, None, None)

        if not key:
            raise SignatureError(
                'failed to load the private key %s' % key_file)
        dsigctx.signKey = key

        if key.setName(key_file) < 0:
            raise SignatureError('failed to set key name')

        if xmlsec.cryptoAppKeyCertLoad(key, cert_file, xmlsec.KeyDataFormatPem) < 0:
            print("Error: failed to load pem certificate \"%s\"" % cert_file)
            return cleanup(doc, dsigctx)

        # sign
        if dsigctx.sign(node) < 0:
            raise SignatureError('signing failed')
        signed_xml = doc.serialize()

    finally:
        if dsigctx:
            dsigctx.destroy()
        if doc:
            doc.freeDoc()
        xmlsec.cryptoShutdown()
        xmlsec.shutdown()
        libxml2.cleanupParser()

    return signed_xml


def cleanup(doc=None, dsig_ctx=None, res=-1):
    if dsig_ctx is not None:
        dsig_ctx.destroy()
    if doc is not None:
        doc.freeDoc()
    return res


def log(msg):
    print ('[%s] %s') % (datetime.datetime.now(), msg)

def decode_base64_and_inflate(b64string):
    decoded_data = base64.b64decode(b64string)
    return zlib.decompress(decoded_data, -15)


def deflate_and_base64_encode(string_val):
    zlibbed_str = zlib.compress(string_val)
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string)


def usage():
    print ('\nUsage: saml_idp.py --debug  '
           '--user=<user>  '
           '--audience=<audience>  '           
           '--saml_issuer=<issuer>  '
           '--key_file=<private_key_file>  '
           '--cert_file=<certificate_file>\n')


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], None,
                                   ["debug", "user=",
                                    "saml_issuer=", "cert_file=",
                                    "key_file=", "audience=", "group="])
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt == "--debug":
            debug_flag = True
        if opt == "--saml_issuer":
            saml_issuer = arg
        if opt == "--user":
            user = arg
        if opt == "--key_file":
            key_file = arg
        if opt == "--cert_file":
            cert_file = arg
        if opt == "--audience":
            audience = arg

    if not key_file or not cert_file:
        print('No private key specified to use for POST binding.')
        usage()
        sys.exit(1)


    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    five_sec_from_now = time.strftime(
        '%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time()+3000))
    samlresp = _generate_response(now, five_sec_from_now, user,
                                  getrandom_samlID(), audience, audience)                            

    samlresp = samlresp.replace("<!DOCTYPE saml2p:Response [\n<!ATTLIST saml2p:Response ID ID #IMPLIED>\n]>\n", "")
    samlresp = samlresp.replace("<!DOCTYPE samlp:Response [\n<!ATTLIST samlp:Response ID ID #IMPLIED>\n]>\n", "")

    print(base64.encodestring(samlresp).replace('\n', ''))
    #print(xml.dom.minidom.parseString(samlresp).toprettyxml())
