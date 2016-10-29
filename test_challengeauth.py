# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (c) 2016 Tyler Mulligan <z@xnz.me> and contributors.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Tested against examples given by quakenet.org:
#   https://www.quakenet.org/development/challengeauth
#

import hashlib
from challengeauth import calculate_password_hash
from challengeauth import calculate_hmac_hash


def challengeauth(username, password, challenge, digest=hashlib.sha256):

    password_hash = calculate_password_hash(password=password, digest=digest)
    confirmation_hash, auth_key = calculate_hmac_hash(username=username, password_hash=password_hash, challenge=challenge, digest=digest)

    return confirmation_hash, password_hash, auth_key


def test_challengeauth_worked_example():
    confirmation_hash, password_hash, auth_key = challengeauth("[fishking]", 'iLOVEfish12345', "3afabede5c2859fd821e315f889d9a6c", hashlib.sha1)
    assert password_hash == '15ccbbd456d321ef98fa1b58e724828619b6066e'
    assert auth_key == 'c05587aeb231e8f90a2df8bc66142c2a8b1be908'
    assert confirmation_hash == 'e683c83fd16a03b6d690ea231b4f346c32ae0aaa'


def test_challengeauth_md5_examples():
    confirmation_hash = challengeauth("mooking", "0000000000", "12345678901234567890123456789012", hashlib.md5)[0]
    assert confirmation_hash == '2ed1a1f1d2cd5487d2e18f27213286b9'

    confirmation_hash = challengeauth("fishking", "ZZZZZZZZZZ", "12345678901234567890123456789012", hashlib.md5)[0]
    assert confirmation_hash == '8990cb478218b6c0063daf08dd7e1a72'


def test_challengeauth_sha1_examples():
    confirmation_hash = challengeauth("mooking", "0000000000", "12345678901234567890123456789012", hashlib.sha1)[0]
    assert confirmation_hash == 'd0328d41426bd2ace183467ce0a6305445e3d497'

    confirmation_hash = challengeauth("fishking", "ZZZZZZZZZZ", "12345678901234567890123456789012", hashlib.sha1)[0]
    assert confirmation_hash == '4de3f1c86dd0f59da44852d507e193c339c4b108'


def test_challengeauth_sha256_examples():
    confirmation_hash = challengeauth("mooking", "0000000000", "12345678901234567890123456789012", hashlib.sha256)[0]
    assert confirmation_hash == 'f6eced34321a69c270472d06c50e959c48e9fd323b2c5d3194f44b50a118a7ea'

    confirmation_hash = challengeauth("fishking", "ZZZZZZZZZZ", "12345678901234567890123456789012", hashlib.sha256)[0]
    assert confirmation_hash == '504056d53b2fc4fd783dc4f086dabc59f845d201e650b96dfa95dacc8cac2892'
