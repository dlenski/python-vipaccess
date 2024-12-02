python-vipaccess
================

[![PyPI](https://img.shields.io/pypi/v/python-vipaccess.svg)](https://pypi.python.org/pypi/python-vipaccess)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Build Status](https://github.com/dlenski/python-vipaccess/workflows/test_and_release/badge.svg)](https://github.com/dlenski/python-vipaccess/actions?query=workflow%3Atest_and_release)

Table of Contents
=================

* [python-vipaccess](#python-vipaccess)
* [Table of Contents](#table-of-contents)
   * [Intro](#intro)
   * [Dependencies](#dependencies)
   * [Installation](#installation)
   * [Usage](#usage)
      * [Provisioning a new VIP Access credential](#provisioning-a-new-vip-access-credential)
      * [Display a QR code to register your credential with mobile TOTP apps](#display-a-qr-code-to-register-your-credential-with-mobile-totp-apps)
      * [Generating access codes using an existing credential](#generating-access-codes-using-an-existing-credential)

This is a fork of [**`cyrozap/python-vipaccess`**](https://github.com/dlenski/python-vipaccess). Main differences:

- No dependency on `qrcode` or `image` libraries; you can easily use
  external tools such as [`qrencode`](https://github.com/fukuchi/libqrencode)
  to convert an `otpauth://` URI to a QR code if needed, so it seems
  unnecessary to build in this functionality.
- Option to generate either the mobile (`SYMC`/`VSMT`) or desktop (`SYDC`/`VSST`)
  versions of the VIP Access tokens; as far as I can tell there is no
  real difference between them, but some clients require one or the
  other specifically. There are also some rarer token types/prefixes
  which can be generated if necessary
  ([reference list from Symantec](https://support.symantec.com/us/en/article.tech239895.html))
- Command-line utility is expanded to support *both* token
  provisioning (creating a new token) and emitting codes for an
  existing token (inspired by the command-line interface of
  [`stoken`](https://github.com/cernekee/stoken), which handles the same functions for [RSA SecurID](https://en.wikipedia.org/wiki/RSA_SecurID) tokens

Intro
-----

python-vipaccess is a free and open source software (FOSS)
implementation of Symantec's VIP Access client (now owned by Broadcom).

If you need to access a network which uses VIP Access for [two-factor
authentication](https://en.wikipedia.org/wiki/Two-factor_authentication),
but can't or don't want to use Symantec's proprietary
applications—which are only available for Windows, MacOS, Android,
iOS—then this is for you.

As [@cyrozap](https://github.com/cyrozap) discovered in reverse-engineering the VIP Access protocol
([original blog
post](https://www.cyrozap.com/2014/09/29/reversing-the-symantec-vip-access-provisioning-protocol)),
Symantec VIP Access actually uses a **completely open standard**
called [Time-based One-time Password
Algorithm](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
for generating the 6-digit codes that it outputs. The only
non-standard part is the **provisioning** protocol used to create a
new token.

Dependencies
------------

-  Python 3.3+ (recommended) or 2.7 (not recommended)
-  [`oath`](https://pypi.python.org/pypi/oath/1.4.1)
-  [`pycryptodome`](https://pypi.python.org/pypi/pycryptodome/3.6.6)
-  [`requests`](https://pypi.python.org/pypi/requests)

For development purposes, you can install the dependencies with `pip install -r requirements.txt` in
the project root directory.

To install `pip` see the [`pip` installation documentation](https://pip.pypa.io/en/stable/installing/).

Installation
------------

Install with [`pip3`](https://pip.pypa.io/en/stable/installing/) to automatically fetch Python
dependencies. (Note that on most systems, `pip3` invokes the Python 3.x version, while `pip` invokes
the Python 2.7 version; Python 2.7 is still supported, but not recommended because it's nearing
obsolescence.)

```console
# Install latest release from PyPI
$ pip3 install python-vipaccess

# Optional - install the version which prints out a QR code (instead of using qrencode)
$ pip3 install 'python-vipaccess[qr]'

# Install latest development version from GitHub
$ pip3 install https://github.com/dlenski/python-vipaccess/archive/HEAD.zip
```

Usage
-----

### Provisioning a new VIP Access credential

This is used to create a new VIP Access token. It connects to https://services.vip.symantec.com/prov
and requests a new token, then deobfuscates it, and checks whether it is properly decoded and
working correctly, via a second request to https://vip.symantec.com/otpCheck.

By default it stores the new token in the file `.vipaccess` in your home directory (in a
format similar to `stoken`), but it can store to another file instead,
or instead just print out the "token secret" string with instructions
about how to use it.

```
usage: vipaccess provision [-h] [-p | -o DOTFILE] [-t TOKEN_MODEL]

optional arguments:
  -h, --help            show this help message and exit
  -p, --print           Print the new credential, but don't save it to a file
  -o DOTFILE, --dotfile DOTFILE
                        File in which to store the new credential (default
                        ~/.vipaccess)
  -i ISSUER, --issuer ISSUER
                        Specify the issuer name to use (default: Symantec)
  -t TOKEN_MODEL, --token-model TOKEN_MODEL
                        VIP Access token model. Often SYMC/VSMT ("mobile"
                        token, default) or SYDC/VSST ("desktop" token). Some
                        clients only accept one or the other. Other more
                        obscure token types also exist:
                        https://support.symantec.com/en_US/article.TECH239895.html
```

Here is an example of the output from `vipaccess provision -p`:

```
Generating request...
Fetching provisioning response from Symantec server...
Getting token from response...
Decrypting token...
Checking token against Symantec server...
Credential created successfully:
	otpauth://totp/VIP%20Access:SYMC12345678?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&issuer=Symantec&algorithm=SHA1&digits=6
This credential expires on this date: 2019-01-15T12:00:00.000Z

You will need the ID to register this credential: SYMC12345678

You can use oathtool to generate the same OTP codes
as would be produced by the official VIP Access apps:

    oathtool    -b --totp AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  # output one code
    oathtool -v -b --totp AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  # ... with extra information
```

Here is the format of the `.vipaccess` token file output from
`vipaccess provision [-o ~/.vipaccess]`. (This file is created with
read/write permissions *only* for the current user.)

```
version 1
secret AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
id SYMC12345678
expiry 2019-01-15T12:00:00.000Z
```

### Display a QR code to register your credential with mobile TOTP apps

Once you generate a token with `vipaccess provision`, use `vipaccess uri` to show the `otpauth://` URI and
[`qrencode`](https://fukuchi.org/works/qrencode/manual/index.html) to display that URI as a QR code:

```
$ qrencode -t UTF8 'otpauth://totp/VIP%20Access:SYMCXXXX?secret=YYYY&issuer=Symantec&algorithm=SHA1&digits=6'
```

Scan the code into your TOTP generating app,
like [FreeOTP](https://freeotp.github.io/) or
[Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2).

### Generating access codes using an existing credential

The `vipaccess [show]` option will also do this for you: by default it
generates codes based on the credential in `~/.vipaccess`, but you can
specify an alternative credential file or specify the OATH "token
secret" on the command line.

```
usage: vipaccess show [-h] [-s SECRET | -f DOTFILE]

optional arguments:
  -h, --help            show this help message and exit
  -s SECRET, --secret SECRET
                        Specify the token secret on the command line (base32
                        encoded)
  -f DOTFILE, --dotfile DOTFILE
                        File in which the credential is stored (default
                        ~/.vipaccess
```

As alluded to above, you can use other standard
[OATH](https://en.wikipedia.org/wiki/Initiative_For_Open_Authentication)-based
tools to generate the 6-digit codes identical to what Symantec's official
apps produce.
