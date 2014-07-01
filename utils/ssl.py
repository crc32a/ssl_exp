from dateutil.tz import tzutc
import OpenSSL.crypto
import datetime
import six
import sys
import os
import re

generalized_fmt  = "([0-9]{4})([0-9]{2})([0-9]{2})"
generalized_fmt += "([0-9]{2})([0-9]{2})([0-9]{2})Z"

generalized_time_re = re.compile(generalized_fmt, re.IGNORECASE)

def full_path(file_name):
    return os.path.abspath(os.path.expanduser(file_name))

class X509(object):
    def __init__(self):
        self.x509 = None


    def not_before(self):
        return self.gmtime_to_datetime(self.x509.get_notBefore())

    def not_after(self):
        return self.gmtime_to_datetime(self.x509.get_notAfter())

    def gmtime_to_datetime(self, general_time):
        m = generalized_time_re.match(general_time)
        if not m:
            raise IOError("could not parse general time")
        day_val = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        time_val = (int(m.group(4)), int(m.group(5)), int(m.group(6)))
        dt_args = day_val + time_val
        return datetime.datetime(*dt_args,tzinfo=tzutc())

    def load_string(self,buff,filetype=OpenSSL.crypto.FILETYPE_PEM):
        self.x509 = OpenSSL.crypto.load_certificate(filetype, buff)
        return self.x509

    def load_file(self,file_name):
        with open(file_name,'rb') as fp:
            buff = fp.read()
        if six.PY3:
            buff = buff.decode()
        return self.load_string(buff)

