# weechat-challengeauth

A WeeChat script for authenticating with QuakeNet using [CHALLENGEAUTH](https://www.quakenet.org/development/challengeauth).

## Installation

* Put `challengeauth.py` in `~/.weechat/python/`
* Create a symbolic link for it in `~/.weechat/python/autoload/` 

```
cd ~/.weechat/python/autoload
ln -s ../challengeauth.py
```

## Options

*You probably won't have to change these*

| Option                     | Default                         | Description                        |
|----------------------------|---------------------------------|------------------------------------|
| `challengeauth_qbot_user`  | `Q@CServe.quakenet.org`         | The qbot user to authenticate to.  |
| `challengeauth_qbot_host`  | `Q!TheQBot@CServe.quakenet.org` | The qbot host for the qbot user.   |

## Tests

Unit tests can be run with `py.test` and coverage tests with `tox`.

## License

Copyright (c) 2016 Tyler Mulligan (z@xnz.me) and contributors.

Distributed under the MIT license. See the LICENSE file for more details.
