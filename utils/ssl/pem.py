import base64
import string
import os

BEG_BLOCK = 1
END_BLOCK = 2

block_type_map = {
    "-----BEGIN CERTIFICATE-----": ("x509", BEG_BLOCK),
    "-----END CERTIFICATE-----": ("x509", END_BLOCK),
    "-----BEGIN RSA PRIVATE KEY-----": ("pkcs1RSA", BEG_BLOCK),
    "-----END RSA PRIVATE KEY-----": ("pkcs1RSA", END_BLOCK)}


def read_file(file_name):
    with open(os.path.expanduser(file_name), "rb") as fp:
        return fp.read()


def pemblock_to_der(pemblock):
    #Strip blank lines cause I don't know they cause problems
    lines = [l for l in pemblock.split("\n") if len(l) > 0]
    if len(lines) < 2:
        raise IOError("Could not base 64 decode pemblock. "
                      "Begin and End lines could not be found")
    base64str = string.join(lines[1:-1], "\n")
    return base64.standard_b64decode(base64str)


def split_pem(pemlines):
    blocktype = None
    pemblocklines = []
    pemblocks = []

    #incase some systems insert \r
    line_num = 0
    for line in pemlines.replace("\r", "").split("\n"):
        line_num += 1
        if line in block_type_map and block_type_map[line][1] == BEG_BLOCK:
            #Handle Begining of block
            if blocktype is not None:
                raise IOError(
                    "Unexpected BEGIN block found "
                    "but was already inside a pem block. "
                    " at line {0}".format(line_num))
            pemblocklines = [line]
            #identify the block type where in
            blocktype = block_type_map[line][0]
            continue

        if line in block_type_map and block_type_map[line][1] == END_BLOCK:
            #Handle the end of block
            if blocktype is None:
                raise IOError(
                    "Unexpected END block found"
                    "But was not in a pem block"
                    " at line {0}".format(line_num))
            pemblocklines.append(line)
            pemblocks.append((blocktype, string.join(pemblocklines, "\n")))
            blocktype = None

        #otherwise handle non beg or end block case
        if blocktype:
            if len(line) > 0:
                #Strip blank lines otherwise append to pemblocklines
                pemblocklines.append(line)
    #At the end of the decode run. Make sure were are outside of a block
    if blocktype is not None:
        raise IOError("reached end of pemblock with out END block found")
    return pemblocks





