from pyasn1.codec.der import decoder
from pyasn1.codec.der import encoder
from pyasn1.type.univ import OctetString
import pyasn1_modules.rfc2459 as rfc2459

from utils.ssl.pem import pemblock_to_der


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


def get_subject_cn(x509_der):
    cn = []
    (x509, spec) = decoder.decode(x509_der, asn1Spec=rfc2459.Certificate())
    tbsCert = x509.getComponentByName("tbsCertificate")
    subjectName = tbsCert.getComponentByName("subject")
    rdnSeq = subjectName.getComponent()
    for rnd in rdnSeq:
        for attr in rnd:
            attrType = attr.getComponentByName("type")
            attrVal = attr.getComponentByName("value")
            if attrType == rfc2459.id_at_commonName:
                dirString = rfc2459.DirectoryString()
                (cnDS, spec) = decoder.decode(attrVal, asn1Spec=dirString)
                cn.append(decode_directory_string(cnDS))
    return cn


def get_subject_cn_from_pem(x509_pem):
    x509_der = pemblock_to_der(x509_pem)
    return get_subject_cn(x509_der)


def get_subject_alt_names(x509_der):
    alt_names_list = []
    (x509, spec) = decoder.decode(x509_der, asn1Spec=rfc2459.Certificate())
    tbsCert = x509.getComponentByName("tbsCertificate");
    exts = tbsCert.getComponentByName("extensions")
    for ext in exts:
        extnID = ext.getComponentByName("extnID")
        critical = ext.getComponentByName("critical")
        extnValue = ext.getComponentByName("extnValue")
        if extnID == rfc2459.id_ce_subjectAltName:
            (octets, spec) = decoder.decode(extnValue, asn1Spec=OctetString())
            (generalNames, spec) = decoder.decode(
                octets, asn1Spec=rfc2459.GeneralNames())
            for generalName in generalNames:
                if generalName.getName() == "dNSName":
                    nameType = generalName.getName()
                    dNSName = generalName.getComponent().asOctets()
                    alt_names_list.append((nameType, dNSName))
    return alt_names_list


def get_subject_alt_names_from_pem(x509_pem):
    x509_der = pemblock_to_der(x509_pem)
    return get_subject_alt_names(x509_der)
