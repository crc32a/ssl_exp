import OpenSSL.crypto
import six
import sys
import os

def full_path(file_name):
    return os.path.abspath(os.path.expanduser(file_name))

class X509(object):
    def __init__(self):
        self.x509 = None


    def load_x509(self,*args,**kw):
        if 'file_name' in kw:
            if(six.PY3):
                buff = open(kw['file_name'],"rb").read().decode()
            else:
                buff = open(kw['file_name'],"rb").read()
        self.x509 = OpenSSL.crypto.load_certificate(buff)
        return self.x509
        
        

