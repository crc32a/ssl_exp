#!/usr/bin/env python

import utils.ssl

xu = utils.ssl.X509()

xu.load_file('./long_date.pem')

nb = xu.not_before()
na = xu.not_after()
