# Securitas

Securitas is a Python library for integrating Symantec VIP two factor authentication into any application.

## Installation

< Temporary, could be wrong, need to test! >

Install:

    $ pip install securitas

## Obtaining a certificate

To use Securitas in your project you first need a certificate from [Symantec VIP manager](https://manager.vip.symantec.com).
To obtain a certificate login and go to Account -> Manage VIP Certificates -> Request a Certificate. From there follow
the directions to create a new certificate. On the download screen select the PKCS#12 format and enter the password you
would like to use to secure the certificate.

After downloading the PKCS#12 certificate, you must split it into a public and private key. To do so run the following two
commands.

Extract the private key:

    $ openssl pkcs12 -in yourP12File.pfx -nocerts -out privateKey.pem

Extract the public certificate:

    $ openssl pkcs12 -in yourP12File.pfx -clcerts -nokeys -out publicCert.pem

You may also want to remove the passphrase from the key:

    $ openssl.exe rsa -in privateKey.pem -out privateKey_nopass.pem

## Usage

Once the certificate is split, Securitas is simple to start using.

```python
from suds.client import Client
from symantec_package.lib.userService.SymantecUserServices import SymantecUserServices

# METHOD #1 for URL from web host
userservices_url = 'http://somelocation.io/vipuserservices-auth-1.7.wsdl'
# METHOD #2 for URL from local directory
import urllib
import os
from urllib.parse import urlparse
from urllib.request import pathname2url
userservices_url = urllib.parse.urljoin('file:', pathname2url(os.path.abspath('../wsdl_files/vipuserservices-auth-1.7.wsdl')))

user_services_client = Client(userservices_url,
      transport = HTTPSClientCertTransport( '../privateKey_nopass.pem', '../publicCert.pem'))

test_user_services_object = SymantecUserServices(user_services_client)
send_push_to_phone_result = test_user_services_object.authenticateUserWithPush("push_123", "my_mobile_device")
# (reply){
#   requestId = "push_123"
#   status = "6040"
#   statusMessage = "Mobile push request sent"
#   transactionId = "<some_id>"
#   pushDetail =
#      (PushDetailType){
#         pushCredentialId = "<some_credential_id>"
#         pushSent = True
#      }
# }

```

## Documentation

https://arrenh.github.io/Securitas/

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ArrenH/Securitas. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.
