from dateutil.tz import tzutc
import OpenSSL.crypto
import datetime
import six
import sys
import os
import re

generalized_fmt = "([0-9]{4})([0-9]{2})([0-9]{2})" \
                  "([0-9]{2})([0-9]{2})([0-9]{2})(.)"\
                  "(([0-9]{2})([0-9]{2}))?"

generalized_time_re = re.compile(generalized_fmt, re.IGNORECASE)


def full_path(file_name):
    return os.path.abspath(os.path.expanduser(file_name))


class X509(object):
    def __init__(self):
        self.x509 = None

    def not_before_after(self):
        not_before = self.gmtime_to_datetime(self.x509.get_notBefore())
        not_after = self.gmtime_to_datetime(self.x509.get_notAfter())
        return not_before, not_after

    def get_subject_alt_name(self):
        alt_names = []
        ext_count = self.x509.get_extension_count()
        for i in xrange(0, ext_count):
            ext = self.x509.get_extension(i)
            if ext.get_short_name() == 'subjectAltName':
                for alt_name in str(ext).split(", "):
                    alt_name_type, alt_name_val = alt_name.split(":")
                    alt_names.append((alt_name_type,alt_name_val))
        return alt_names

    @staticmethod
    def gmtime_to_datetime(general_time):
        m = generalized_time_re.match(general_time)
        if not m:
            raise IOError('could not parse general time')
        day_val = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        time_val = (int(m.group(4)), int(m.group(5)), int(m.group(6)))
        dt_args = day_val + time_val
        dt = datetime.datetime(*dt_args,tzinfo=tzutc())
        if m.group(7).lower() == 'z':
            return dt
        if m.group(7) == '+':
            diff_hour = 0 - datetime.timedelta(hours=int(m.group(9)))
            diff_min = 0 - datetime.timedelta(minutes=int(m.group(10)))
            return dt + diff_hour + diff_min
        if m.group(7) == '-':
            diff_hour = datetime.timedelta(hours=int(m.group(9)))
            diff_min = datetime.timedelta(minutes=int(m.group(10)))
            return dt + diff_hour + diff_min
        raise IOError('Unabled to decode generalized time')

    def loads(self, buff, filetype=OpenSSL.crypto.FILETYPE_PEM):
        self.x509 = OpenSSL.crypto.load_certificate(filetype, buff)
        return self.x509

    def dumps(self,filetype=OpenSSL.crypto.FILETYPE_PEM):
        return OpenSSL.crypto.dump_certificate(filetype,self.x509)

    def load_file(self, file_name, filetype=OpenSSL.crypto.FILETYPE_PEM):
        with open(file_name,'rb') as fp:
            buff = fp.read()
        if six.PY3:
            buff = buff.decode()
        return self.loads(buff, filetype=filetype)

