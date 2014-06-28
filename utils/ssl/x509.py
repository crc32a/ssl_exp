from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type.univ import OctetString
import pyasn1_modules.rfc2459 as rfc2459
from dateutil.tz import tzutc
import datetime
import six

from utils.ssl import pem
import re

utc_re = re.compile("([0-9]{12})(.)(.*)")
diff_re = re.compile("[0-9]{12}(.)([0-9]{4})")
general_time_re = re.compile("([0-9]{14})(.)")


def bytes_to_str(octets):
    if six.PY3:
        return octets.decode()
    return octets


def validity_generaltime_to_datetime(general_time):
    date_string = bytes_to_str(general_time.getComponent().asOctets())
    m = general_time_re.match(date_string)
    if not m:
        raise IOError("Unrecognized generalTime string")
    date_nums = m.group(1)
    (year, month) = (int(date_nums[0:4]), int(date_nums[4:6]))
    (day, hour) = (int(date_nums[6:8]), int(date_nums[8:10]))
    (mins, secs) = (int(date_nums[10:12]), int(date_nums[12:14]))
    #rfc 2459 says generaltime validities must always be in UTC
    if m.group(2).lower() != "z":
        raise IOError("generalTime validity must be in UTC timezone")
    return datetime.datetime(
        year, month, day, hour, mins, secs, tzinfo=tzutc())


def validity_utctime_to_datetime(utc_time):
    date_string = bytes_to_str(utc_time.getComponent().asOctets())
    m = utc_re.match(date_string)
    if not m:
        raise IOError("Did not recognize {0} as a a utcTime".format(bytes))
    #format for utcTime is YYMMDDHHmmssZ for zulu
    date_nums = m.group(1)
    (year, month) = (int(date_nums[0:2]), int(date_nums[2:4]))
    (day, hour) = (int(date_nums[4:6]), int(date_nums[6:8]))
    (mins, secs) = (int(date_nums[8:10]), int(date_nums[10:12]))
    #rfc 2459 is using some brain damaged encoding of 100 years in
    #a 2 digit ascii value. so 13 means 2013 and 64 means 1964 with 1950 as
    #the epoch and a y2k like bug at 2050
    if year >= 50:
        year += 1900
    else:
        year += 2000
    dt = datetime.datetime(
        year, month, day, hour, mins, secs, tzinfo=tzutc())
    #a z means we're already in UTC time so just return this
    if m.group(2).lower() == "z":
        return dt
    d = diff_re.match(date_string)
    if not m:
        raise IOError("Unrecognized time differential")
    #Otherwise compute UTC based on the time differential
    diff_string = d.group(2)
    diff_hours = int(diff_string[0:2])
    diff_mins = int(diff_string[2:4])
    if d.group(1) == "+":
        dt -= datetime.timedelta(hours=diff_hours)
        dt -= datetime.timedelta(minutes=diff_mins)
    else:
        dt += datetime.timedelta(hours=diff_hours)
        dt += datetime.timedelta(minutes=diff_mins)
    return dt


def validity_to_datetime(tv):
    if tv.getName() == "utcTime":
        return validity_utctime_to_datetime(tv)
    elif tv.getName() == "generalTime":
        return validity_generaltime_to_datetime(tv)
    else:
        raise IOError("unrecognized datetime format")


def decode_directory_string(ds):
    if ds.getName() == "teletexString":
        return bytes(ds.getComponent()).decode("ascii")
    if ds.getName() == "printableString":
        return bytes(ds.getComponent()).decode("ascii")
    if ds.getName() == "universalString":
        return bytes(ds.getComponent()).decode("utf-32-be")
        #UniversalString is deprecated and poorly documented
        #We took the liberty to assume BigEndian format
    if ds.getName() == "utf8String":
        return bytes(ds.getComponent()).decode("utf-8")
    if ds.getName() == "bmpString":
        return bytes(ds.getComponent()).decode("utf-16-be")
    if ds.getName() == "ia5String":
        return bytes(ds.getComponent()).decode("ascii")
    return bytes(ds.getComponent()).decode("utf-8")


def get_cn_from_rdn_set(rdn_seq):
    cn = []
    #Iterate throuh the rdn sequence untill you find 2.5.4.3
    for rdn in rdn_seq:
        for attr in rdn:
            attr_type = attr.getComponentByName("type")
            attr_val = attr.getComponentByName("value")
            if attr_type == rfc2459.id_at_commonName:
                dir_string = rfc2459.DirectoryString()
                (cn_ds, spec) = decoder.decode(attr_val, asn1Spec=dir_string)
                cn.append(decode_directory_string(cn_ds))
    return cn


def get_subject_name(x509_der):
    (x509, spec) = decoder.decode(x509_der, asn1Spec=rfc2459.Certificate())
    tbs_crt = x509.getComponentByName("tbsCertificate")
    subj_name = tbs_crt.getComponentByName("subject")
    return subj_name


def get_cn_from_name(name):
    rdn_seq = name.getComponent()
    return get_cn_from_rdn_set(rdn_seq)


def get_subject_cn(x509_der):
    subject_name = get_subject_name(x509_der)
    cn = get_cn_from_name(subject_name)
    return cn


def get_validity_dates(x509_der):
    (x509, spec) = decoder.decode(x509_der, asn1Spec=rfc2459.Certificate())
    tbs_crt = x509.getComponentByName("tbsCertificate")
    validity = tbs_crt.getComponentByName("validity")
    not_before = validity.getComponentByName("notBefore")
    not_after = validity.getComponentByName("notAfter")

    not_before_dt = validity_to_datetime(not_before)
    not_after_dt = validity_to_datetime(not_after)
    dates = (not_before_dt, not_after_dt)
    return dates


#I'm sure I dont need to do this manually so when I find a lib
#That handles this I'll stop using it
def x509_pem_to_der(x509_pem):
    pem_blocks = pem.split_pem(x509_pem)
    if len(pem_blocks) <= 0:
        raise IOError("no pemblocks found")
    if pem_blocks[0][0] != "x509":
        raise IOError("pemblock was not an X509 certificate")
    der = pem.pem_to_der(pem_blocks[0][1], 1, 1)
    return der


def get_subject_alt_names(x509_der):
    alt_names_list = []
    (x509, spec) = decoder.decode(x509_der, asn1Spec=rfc2459.Certificate())
    tbs_crt = x509.getComponentByName("tbsCertificate")
    exts = tbs_crt.getComponentByName("extensions")
    for ext in exts:
        ext_id = ext.getComponentByName("extnID")
        critical = ext.getComponentByName("critical")
        ext_val = ext.getComponentByName("extnValue")
        if ext_id == rfc2459.id_ce_subjectAltName:
            (octets, spec) = decoder.decode(ext_val, asn1Spec=OctetString())
            (general_names, spec) = decoder.decode(
                octets, asn1Spec=rfc2459.GeneralNames())
            #Where only looking for dNSNames or the cn
            #  fields of a directoryName
            for general_name in general_names:
                name_type = general_name.getName()
                if name_type == "dNSName":
                    octets = general_name.getComponent().asOctets()
                    dns_name = bytes_to_str(octets)
                    alt_names_list.append((name_type, dns_name))
                if name_type == "directoryName":
                    dir_name = general_name.getComponent()
                    for cn in get_cn_from_name(dir_name):
                        alt_names_list.append(("cn", cn))
    return alt_names_list