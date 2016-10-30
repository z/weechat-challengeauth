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

#
# Authenticate with QuakeNet using CHALLENGEAUTH
#   https://www.quakenet.org/development/challengeauth
#
# Thank You:
#   Dominik Honnef: for challengeauth.rb which I used as a reference
#     https://weechat.org/scripts/source/challengeauth.rb.html/
#
#   Petr Zemek: for his repository structure
#     https://github.com/s3rvac/weechat-notify-send
#
#   Sébastien Helleu: for WeeChat, great documentation and references
#
# After loading this script, you can use the command /challengeauth
#   /challengeauth [username] [password]
#
# History:
#
# 2016-10-29, Tyler Mulligan <z@xnz.me>
#     version 0.1.1: Incorrectly called this a 'plugin', it's a script.
#
# 2016-10-29, Tyler Mulligan <z@xnz.me>
#     version 0.1.0: Initial release, feature-matching challengeauth.rb

import hashlib
import hmac
import sys
from collections import namedtuple

SCRIPT_NAME     = "challengeauth"
SCRIPT_AUTHOR   = "z <z@xnz.me>"
SCRIPT_VERSION  = "0.1.1"
SCRIPT_LICENSE  = "MIT"
SCRIPT_DESC     = "Authenticate with QuakeNet using CHALLENGEAUTH"
SCRIPT_COMMAND  = "challengeauth"
SCRIPT_ARGS     = "[username] [password]"
SCRIPT_CLOSE_CB = "close_cb"

OPTIONS = {
    'challengeauth_qbot_user': (
        'Q@CServe.quakenet.org',
        'The qbot user to authenticate to.'
    ),
    'challengeauth_qbot_hostmask': (
        'Q!TheQBot@CServe.quakenet.org',
        'The qbot challengeauth_qbot_hostmask for the qbot user.'
    ),
}

import_ok = True

Request = namedtuple('Request', ['username', 'hash'])

# Ensure that we are running under WeeChat.
try:
    import weechat
except ImportError:
    print('This script has to run under WeeChat (https://weechat.org/).')
    import_ok = False


def close_cb(*kwargs):
    return weechat.WEECHAT_RC_OK


def default_value_of(option):
    return OPTIONS[option][0]


def add_default_value_to(description, default_value):
    """Adds the given default value to the given option description."""
    # All descriptions end with a period, so do not add another period.
    return '{} Default: {}.'.format(
        description,
        default_value if default_value else '""'
    )


def get_server_buffer(server):
    return weechat.buffer_search("irc", "server." + server)


def quakenet_lowercase(string):
    lowercase_string = string

    # was specified https://www.quakenet.org/development/challengeauth
    lower_symbols = {
        '[': '{',
        ']': '}',
    }

    for i, j in lower_symbols.items():
        lowercase_string = lowercase_string.replace(i, j)

    return lowercase_string


def calculate_password_hash(password, digest=hashlib.sha256):
    truncated_password = password[:10]
    password_hash = digest(truncated_password.encode('utf-8')).hexdigest()
    return password_hash


def calculate_hmac_hash(username, password_hash, challenge, digest=hashlib.sha256):

    lowercase_username = quakenet_lowercase(username)
    auth_string = "{}:{}".format(lowercase_username, password_hash)
    auth_key = digest(auth_string.encode('utf-8')).hexdigest()

    if int(sys.version_info.major) == 3:
        response = hmac.HMAC(bytes(auth_key, 'utf-8'), challenge.encode('utf-8'), digestmod=digest)
    else:
        response = hmac.HMAC(auth_key, challenge.encode('utf-8'), digestmod=digest)

    return response.hexdigest(), auth_key


def challenge_notice(modifier, data, server, line):

    server_buffer = get_server_buffer(server)

    if server not in requests:
        return line
    else:
        request = requests[server]

    parts = line.split()

    if len(parts) < 5:
        weechat.prnt("", "Response had more arguments than expected")
        return line

    hostmask = parts[0][1::]
    command = parts[3][1::]
    challenge = parts[4]

    if hostmask != qbot_hostmask:
        weechat.prnt("", "Response from wrong user")
        return line

    if command != 'CHALLENGE':
        weechat.prnt("", "Response was not expected command: CHALLENGE")
        return line

    confirmation_hash, auth_key = calculate_hmac_hash(username=request.username, password_hash=request.hash, challenge=challenge)

    weechat.prnt("", "Sending CHALLENGEAUTH for {}...".format(request.username))
    weechat.command(server_buffer,
                    "/quote PRIVMSG {} :CHALLENGEAUTH {} {} HMAC-SHA-256".format(qbot_user, request.username, confirmation_hash))

    del confirmation_hash
    del auth_key
    del requests[server]

    return line


def challengeauth(data, buffer, args):
    plugin = weechat.buffer_get_string(buffer, "localvar_plugin")
    if plugin != "irc":
        weechat.prnt("", "/challengeauth only works for IRC buffers.")
        return weechat.WEECHAT_RC_ERROR

    server = weechat.buffer_get_string(buffer, "localvar_server")
    args = args.split()
    username = args[0]
    password = args[1]
    password_hash = calculate_password_hash(password=password)

    requests[server] = Request(username, password_hash)
    server_buffer = get_server_buffer(server)

    weechat.prnt("", "Authenticating as {}...".format(username))
    weechat.command(server_buffer, "/quote PRIVMSG {} :CHALLENGE".format(qbot_user))

    return weechat.WEECHAT_RC_OK


if __name__ == "__main__" and import_ok:
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION,
                        SCRIPT_LICENSE, SCRIPT_DESC, SCRIPT_CLOSE_CB, ""):

        for option, (default_value, description) in OPTIONS.items():
            description = add_default_value_to(description, default_value)
            weechat.config_set_desc_plugin(option, description)
            if not weechat.config_is_set_plugin(option):
                weechat.config_set_plugin(option, default_value)

        requests = {}
        qbot_user = weechat.config_get_plugin('challengeauth_qbot_user')
        qbot_hostmask = weechat.config_get_plugin('challengeauth_qbot_hostmask')

        weechat.hook_command(SCRIPT_COMMAND,
                             SCRIPT_DESC,
                             SCRIPT_ARGS,
                             "",
                             "",
                             "challengeauth",
                             "",
                             )

        weechat.hook_modifier("irc_in_notice", "challenge_notice", "")
