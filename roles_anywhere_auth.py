import base64, datetime, hashlib
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json

# From 900 to 3600
duration_seconds = 3600

# Roles Anywhere Profile ARN
profile_arn = "arn:aws:rolesanywhere:ap-south-1:xxxxxxxxx:profile/xxxxxxxxxxx" 

# IAM Role ARN
role_arn = "arn:aws:iam::xxxxxxxxxx:role/xxxxxxxxxx"
session_name = 'assume_role_session'

# Roles Anywhere Trust Anchor ARN
trust_anchor_arn = "arn:aws:rolesanywhere:ap-south-1:xxxxxxxxxxx:trust-anchor/xxxxxxxxxxxx"

# AWS Region 
region = profile_arn.split(":")[3]

# ************* REQUEST VALUES *************
method = 'POST'
service = 'rolesanywhere'
host = '{}.{}.amazonaws.com'.format(service, region)
endpoint = 'https://{}'.format(host)

# POST requests use a content type header.
content_type = 'application/json'

# Create a date for headers and the credential string
today = datetime.datetime.utcnow()
amz_date = today.strftime('%Y%m%dT%H%M%SZ')

# Date w/o time, used in credential scope
date_stamp = today.strftime('%Y%m%d') 

# AMC PCA Certificate pem file data
cert_pem_data = """-----BEGIN CERTIFICATE-----
MIIDsjCCApqgAwIBAgIUeG05bf+3JF/ci6atl3e1Uws5UGEwDQYJKoZIhvcNAQEL
Dw5z6/qYxlZAmyNcEV7rVxDuqAMKkZmXzaahlyf/mMXo4g5hg6pVpxvSa5yNZqVo
tbHnIJcctRy+YU0zHU8TokyLOs5izCWyUXUC/almCjWjvlyiptzp+sd4LdEEzPZ3
AcQspvENSUKz8qcl853JH2+nkO/3Lb/wOeLbq69lFM1ZCyKENjM=
-----END CERTIFICATE-----"""

private_key_data = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2iPS3eCY8za+rSqr/i5A1J1O41iR4BM3T0Dyyo+e2Gf0/rjy
4h4BAoGBAPM26gRp571f8if4HKsSRzNGDr4l2mrZ/sudlTW7n7viK6HWg2rDHTWA
ASkOPov63/VRUqyf9VbLgH13qgmhTx051puTOc/cESPSGayqC6VIXYwy3U8W387p
9ytQk62U8o73EultF1kXQVrgSJQSXzGEqbzARfafacstukyyMGRZ
-----END RSA PRIVATE KEY-----"""

pass_phrase = ""

# Request parameters for CreateSession--passed in a JSON block.
payload = json.dumps({
            "durationSeconds": duration_seconds,
            "profileArn": profile_arn,
            "roleArn": role_arn,
            "sessionName": session_name,
            "trustAnchorArn": trust_anchor_arn
            })

# Load public certificate
cert = x509.load_pem_x509_certificate(cert_pem_data.strip().encode("utf-8"))

# Load private key
try:
  private_key = serialization.load_pem_private_key(private_key_data.strip().encode("utf-8"), None)
except:
    print('encrypted')
    try:
      private_key = serialization.load_pem_private_key(private_key_data.strip().encode("utf-8"),\
                       password=str.encode(pass_phrase))
    except:
        print('wrong passphrase')

# X509 bash64 encoded DER data
amz_x509 = str(base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.DER)),'utf-8')
 
# Public certificate serial number
ca_serial_number = str(cert.serial_number)
 
# ************* TASK 1: CREATE A CANONICAL REQUEST *************
# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
# Step 1 is to define the verb (GET, POST, etc.)--already done.
# Step 2: Create canonical URI--the part of the URI from domain to query 
# string (use '/' if no path)
canonical_uri = '/sessions'
 
## Step 3: Create the canonical query string. In this example, request
# parameters are passed in the body of the request and the query string
# is blank.
canonical_querystring = ''
 
# Step 4: Create the canonical headers. Header names must be trimmed
# and lowercase, and sorted in code point order from low to high.
# Note that there is a trailing \n.
canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' \
                            + amz_date + '\n' + 'x-amz-x509:' + amz_x509 + '\n'
 
# Step 5: Create the list of signed headers. This lists the headers
# in the canonical_headers list, delimited with ";" and in alpha order.
# Note: The request can include any headers; canonical_headers and
# signed_headers include those that you want to be included in the
# hash of the request. "Host" and "x-amz-date" are always required.
# For Roles Anywhere, content-type and x-amz-x509 are also required.
signed_headers = 'content-type;host;x-amz-date;x-amz-x509'
 
# Step 6: Create payload hash. In this example, the payload (body of
# the request) contains the request parameters.
payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
 
# Step 7: Combine elements to create canonical request
canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + \
                        canonical_headers + '\n' + signed_headers + '\n' + payload_hash
 
# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Match the algorithm to the hashing algorithm you use, SHA-256
algorithm = 'AWS4-X509-RSA-SHA256'
credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' + \
                    hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
 
# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Sign the string_to_sign using the private_key and hex encode
signature = private_key.sign(
    data=string_to_sign.encode('utf-8'),
    padding=padding.PKCS1v15(),
    algorithm=hashes.SHA256()
)
signature_hex = signature.hex()
 
# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
# Put the signature information in a header named Authorization.
authorization_header = algorithm + ' ' + 'Credential=' + ca_serial_number + '/' + credential_scope + ', ' \
                        +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature_hex
 
# For Roles Anywhere, the request  MUST include "host", "x-amz-date",
# "x-amz-x509", "content-type", and "Authorization". Except for the authorization
# header, the headers must be included in the canonical_headers and signed_headers values, as
# noted earlier. Order here is not significant.
# # Python note: The 'host' header is added automatically by the Python 'requests' library.
headers = {'Content-Type':content_type,
           'X-Amz-Date':amz_date,
           'X-Amz-X509':amz_x509,
           'Authorization':authorization_header}
 
# ************* SEND THE REQUEST *************
print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
print('Request URL = ' + endpoint)
 
r = requests.post(endpoint + canonical_uri, data=payload, headers=headers)
 
print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
print('Response code: %d\n' % r.status_code)
print(r.text)
