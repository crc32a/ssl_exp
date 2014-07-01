#!/usr/bin/env python

import utils.ssl
import sys

xu = utils.ssl.X509()

if len(sys.argv) >= 2:
    file_name = sys.argv[1]
else:
    file_name = './cr1.pem'

xu.load_file(file_name)
(nb, na) = xu.not_before_after()

x = xu.x509

sys.stdout.write("not befor: {0}\n".format(nb))
sys.stdout.write("not after: {0}\n".format(na))

alt_names = xu.get_subject_alt_name()
for (alt_name_type, alt_name_val) in alt_names:
    sys.stdout.write("{0}: {1}\n".format(alt_name_type,alt_name_val))

