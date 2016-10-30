# weechat-challengeauth

A WeeChat script for authenticating with QuakeNet using [CHALLENGEAUTH](https://www.quakenet.org/development/challengeauth).

[![Build Status](https://travis-ci.org/z/weechat-challengeauth.svg?branch=develop)](https://travis-ci.org/z/weechat-challengeauth)

## Installation

* Put `challengeauth.py` in `~/.weechat/python/`
* Create a symbolic link for it in `~/.weechat/python/autoload/` 

```
mkdir -p ~/.weechat/python/autoload
wget https://raw.githubusercontent.com/z/weechat-challengeauth.py -P ~/.weechat/python/
cd ~/.weechat/python/autoload && ln -s ../challengeauth.py
```

## Options

*You probably won't have to change these*

| Option                         | Default                             | Description                        |
|--------------------------------|-------------------------------------|------------------------------------|
| `challengeauth_qbot_user`      | `Q@CServe.quakenet.org`             | The Q bot user to authenticate to. |
| `challengeauth_qbot_hostmask`  | `Q!TheQBot@CServe.quakenet.org`     | The hostmask for the Q bot user.   |

## Tests

Unit tests can be run with `py.test` and coverage tests with `tox`.

## License

Copyright (c) 2016 Tyler Mulligan (z@xnz.me) and contributors.

Distributed under the MIT license. See the LICENSE file for more details.
