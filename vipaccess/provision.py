# -*- coding: utf-8 -*-
#
#   Copyright 2014 Forest Crossman
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


from __future__ import print_function

import base64
import binascii
import hashlib
import hmac
import string
import sys
import time
# Python 2/3 compatibility
try:
    import urllib.parse as urllib
except ImportError:
    import urllib

import requests
from Crypto.Cipher import AES
from Crypto.Random import random
from lxml import etree
from oath import totp


PROVISIONING_URL = 'https://services.vip.symantec.com/prov'

TEST_URL = 'https://vip.symantec.com/otpCheck'

HMAC_KEY = b'\xdd\x0b\xa6\x92\xc3\x8a\xa3\xa9\x93\xa3\xaa\x26\x96\x8c\xd9\xc2\xaa\x2a\xa2\xcb\x23\xb7\xc2\xd2\xaa\xaf\x8f\x8f\xc9\xa0\xa9\xa1'

TOKEN_ENCRYPTION_KEY = b'\x01\xad\x9b\xc6\x82\xa3\xaa\x93\xa9\xa3\x23\x9a\x86\xd6\xcc\xd9'

REQUEST_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8" ?>
<GetSharedSecret Id="%(timestamp)d" Version="2.0"
    xmlns="http://www.verisign.com/2006/08/vipservice"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <TokenModel>%(token_model)s</TokenModel>
    <ActivationCode></ActivationCode>
    <OtpAlgorithm type="%(otp_algorithm)s"/>
    <SharedSecretDeliveryMethod>%(shared_secret_delivery_method)s</SharedSecretDeliveryMethod>
    <DeviceId>
        <Manufacturer>%(manufacturer)s</Manufacturer>
        <SerialNo>%(serial)s</SerialNo>
        <Model>%(model)s</Model>
    </DeviceId>
    <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"
        xmlns:vip="http://www.verisign.com/2006/08/vipservice">
        <AppHandle>%(app_handle)s</AppHandle>
        <ClientIDType>%(client_id_type)s</ClientIDType>
        <ClientID>%(client_id)s</ClientID>
        <DistChannel>%(dist_channel)s</DistChannel>
        <ClientInfo>
            <os>%(os)s</os>
            <platform>%(platform)s</platform>
        </ClientInfo>
        <ClientTimestamp>%(timestamp)d</ClientTimestamp>
        <Data>%(data)s</Data>
    </Extension>
</GetSharedSecret>'''


def generate_request(**request_parameters):
    '''Generate a token provisioning request.'''
    default_model = 'MacBookPro%d,%d' % (random.randint(1, 12), random.randint(1, 4))
    default_request_parameters = {
        'timestamp':int(time.time()),
        'token_model':'VSST',
        'otp_algorithm':'HMAC-SHA1-TRUNC-6DIGITS',
        'shared_secret_delivery_method':'HTTPS',
        'manufacturer':'Apple Inc.',
        'serial':''.join(random.choice(string.digits + string.ascii_uppercase) for x in range(12)),
        'model':default_model,
        'app_handle':'iMac010200',
        'client_id_type':'BOARDID',
        'client_id':'Mac-' + ''.join(random.choice('0123456789ABCDEF') for x in range(16)),
        'dist_channel':'Symantec',
        'platform':'iMac',
        'os':default_model,
    }

    default_request_parameters.update(request_parameters)
    request_parameters = default_request_parameters

    data_before_hmac = u'%(timestamp)d%(timestamp)d%(client_id_type)s%(client_id)s%(dist_channel)s' % request_parameters
    request_parameters['data'] = base64.b64encode(
        hmac.new(
            HMAC_KEY,
            data_before_hmac.encode('utf-8'),
            hashlib.sha256
            ).digest()
        ).decode('utf-8')

    return REQUEST_TEMPLATE % request_parameters

def get_provisioning_response(request, session=requests):
    return session.post(PROVISIONING_URL, data=request)

def get_token_from_response(response_xml):
    '''Retrieve relevant token details from Symantec's provisioning
    response.'''
    # Define an arbitrary namespace "vipservice" because lxml doesn't like it
    # when it's "None"
    ns = {'v':'http://www.verisign.com/2006/08/vipservice'}

    tree = etree.fromstring(response_xml)
    result = tree.find('v:Status/v:StatusMessage', ns).text

    if result == 'Success':
        token = {}
        token['timeskew'] = time.time() - int(tree.find('v:UTCTimestamp', ns).text)
        container = tree.find('v:SecretContainer', ns)
        encryption_method = container.find('v:EncryptionMethod', ns)
        token['salt'] = base64.b64decode(encryption_method.find('v:PBESalt', ns).text)
        token['iteration_count'] = int(encryption_method.find('v:PBEIterationCount', ns).text)
        token['iv'] = base64.b64decode(encryption_method.find('v:IV', ns).text)

        device = container.find('v:Device', ns)
        secret = device.find('v:Secret', ns)
        data = secret.find('v:Data', ns)
        expiry = secret.find('v:Expiry', ns)
        usage = secret.find('v:Usage', ns)

        token['id'] = secret.attrib['Id']
        token['cipher'] = base64.b64decode(data.find('v:Cipher', ns).text)
        token['digest'] = base64.b64decode(data.find('v:Digest', ns).text)
        token['expiry'] = expiry.text
        token['period'] = int(usage.find('v:TimeStep', ns).text)

        algorithm = usage.find('v:AI', ns).attrib['type'].split('-')
        if len(algorithm)==4 and algorithm[0]=='HMAC' and algorithm[2]=='TRUNC' and algorithm[3].endswith('DIGITS'):
            token['algorithm'] = algorithm[1].lower()
            token['digits'] = int(algorithm[3][:-6])
        else:
            raise RuntimeError('unknown algorithm %r' % '-'.join(algorithm))

        return token

def decrypt_key(token_iv, token_cipher):
    '''Decrypt the OTP key using the hardcoded AES key.'''
    decryptor = AES.new(TOKEN_ENCRYPTION_KEY, AES.MODE_CBC, token_iv)
    decrypted = decryptor.decrypt(token_cipher)

    # "decrypted" has PKCS#7 padding on it, so we need to remove that
    if type(decrypted[-1]) != int:
        num_bytes = ord(decrypted[-1])
    else:
        num_bytes = decrypted[-1]
    otp_key = decrypted[:-num_bytes]

    return otp_key

def generate_otp_uri(token, secret, issuer='Symantec'):
    '''Generate the OTP URI.'''
    token_parameters = {}
    token_parameters['otp_type'] = urllib.quote('totp')
    token_parameters['app_name'] = urllib.quote('VIP Access')
    token_parameters['account_name'] = urllib.quote(token.get('id', 'Unknown'))
    secret = base64.b32encode(secret).upper()
    token_parameters['parameters'] = urllib.urlencode(
        dict(
            secret=secret,
            digits=token.get('digits', 6),
            period=token.get('period', 30),
            algorithm=token.get('algorithm', 'SHA1').upper(),
            issuer=issuer
            )
        )

    return 'otpauth://%(otp_type)s/%(app_name)s:%(account_name)s?%(parameters)s' % token_parameters

def check_token(token_id, secret, session=requests):
    '''Check the validity of the generated token.'''
    otp = totp(binascii.b2a_hex(secret).decode('utf-8'))
    test_url = 'https://vip.symantec.com/otpCheck'
    token_check = session.post(
        TEST_URL,
        data={
            'cr1':otp[0],
            'cr2':otp[1],
            'cr3':otp[2],
            'cr4':otp[3],
            'cr5':otp[4],
            'cr6':otp[5],
            'cred':token_id,
            'continue':'otp_check'
            }
        )
    if "Your VIP Credential is working correctly" in token_check.text:
        return True
    elif "Your VIP credential needs to be sync" in token_check.text:
        return False
    else:
        return None
