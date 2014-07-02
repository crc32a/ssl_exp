#!/usr/bin/env python

import pyasn1.codec.der.decoder as decoder
import pyasn1_modules.rfc2459 as rfc2459
import utils.ssl
import utils.pem
import sys
import json

xu = utils.ssl.X509()

if len(sys.argv) >= 2:
    file_name = sys.argv[1]
else:
    file_name = './certs.json'

pems = json.loads(utils.pem.read_file(file_name))

i = -1
for(pem_data) in pems:
    i += 1
    try:
        x509 = xu.loads(pem_data)
    except:
        sys.stdout.write("Skipping cert %i cause its bad\n"%i)
    sys.stdout.write("cert[%i]\n"%i)
    (nb,na) = xu.not_before_after()
    for (name_type, name) in xu.get_subject_alt_name():
        sys.stdout.write("\"%s\": \"%s\"\n"%(name_type,name))
