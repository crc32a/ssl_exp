#!/usr/bin/env python

import sys
from utils.ssl.pem import *
from utils.ssl.x509 import *

from pyasn1.codec.der import decoder, encoder
import pyasn1_modules.rfc2459 as rfc2459

if len(sys.argv) >= 2:
    pem = read_file(sys.argv[1])
else:
    pem = read_file("./cr3.pem")

der = x509_pem_to_der(pem)


for (altNameType, altName) in get_subject_alt_names(der):
    print("{0}: {1}".format(altNameType,altName))


cns = get_subject_cn(der)
print("")
print("commonNames:")
for cn in cns:
    print("    \"{0}\"".format(cn))

(nb, na) = get_validity_dates(der)
print("validity:")
print("    not before: {0}".format(nb))
print("    not after: {0}".format(na))

