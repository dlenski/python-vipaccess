from __future__ import print_function

import os, sys
import argparse
import oath
import time
import base64
import re
from vipaccess.patharg import PathType
from vipaccess.version import __version__
from vipaccess import provision as vp

EXCL_WRITE = 'x' if sys.version_info>=(3,3) else 'wx'
TOKEN_MODEL_REFERENCE_PAGE = 'https://support.symantec.com/us/en/article.tech239895.html'

# http://stackoverflow.com/a/26379693/20789

def set_default_subparser(self, name, args=None):
    """default subparser selection. Call after setup, just before parse_args()
    name: is the name of the subparser to call by default
    args: if set is the argument list handed to parse_args()

    , tested with 2.7, 3.2, 3.3, 3.4
    it works with 2.6 assuming argparse is installed
    """
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help']:  # global help if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)

def check_token_model(val):
    if not re.match(r'\w{3,4}$', val):
        raise argparse.ArgumentTypeError('must be 3-4 alphanumeric characters')
    return val

argparse.ArgumentParser.set_default_subparser = set_default_subparser

########################################

def provision(p, args):
    print("Generating request...")
    request = vp.generate_request(token_model=args.token_model)
    print("Fetching provisioning response from Symantec server...")
    session = vp.requests.Session()
    response = vp.get_provisioning_response(request, session)
    print("Getting token from response...")
    try:
        otp_token = vp.get_token_from_response(response.content)
    except RuntimeError as e:
        if e.args == ('Unsupported token model', '4E0D'):
            p.error("Unsupported token model {!r}.\n"
                    "     See list at {}".format(
                    args.token_model, TOKEN_MODEL_REFERENCE_PAGE))
        p.error('Provisioning server error {}: {}'.format(
            e.args[1], e.args[0]))
    print("Decrypting token...")
    otp_secret = vp.decrypt_key(otp_token['iv'], otp_token['cipher'])
    otp_secret_b32 = base64.b32encode(otp_secret).upper().decode('ascii')
    print("Checking token against Symantec server...")
    if not vp.check_token(otp_token, otp_secret, session):
        p.error("Something went wrong--the token could not be validated.\n"
                "    (Check your system time; it differs from the server's by %d seconds)\n" % otp_token['timeskew'])
    elif otp_token.get('period') and otp_token['timeskew'] > otp_token['period']/10:
        p.error("Your system time differs from the server's by %d seconds;\n"
                "    The offset would be 'baked in' to the newly-created token.\n"
                "    Fix system time and try again." % otp_token['timeskew'])

    if args.print:
        otp_uri = vp.generate_otp_uri(otp_token, otp_secret, args.issuer)
        print('Credential created successfully:\n\t' + otp_uri)
        print("This credential expires on this date: " + otp_token['expiry'])
        print('\nYou will need the ID to register this credential: ' + otp_token['id'])
        print('\nYou can use oathtool to generate the same OTP codes')
        print('as would be produced by the official VIP Access apps:\n')
        d = '-d{} '.format(otp_token['digits']) if otp_token['digits']!=6 else ''
        if otp_token['period'] is not None and otp_token['counter'] is None:
            s = '-s{} '.format(otp_token['period']) if otp_token['period']!=30 else ''
            print('    oathtool    {}{}-b --totp {}  # output one code'''.format(d, s, otp_secret_b32))
            print('    oathtool -v {}{}-b --totp {}  # ... with extra information'''.format(d, s, otp_secret_b32))
        elif otp_token['counter'] is not None:
            c = otp_token['counter']
            print('    oathtool    {}-c{} -b --hotp {}  # output next code (need to increment counter each time!)'''.format(d, c, otp_secret_b32))
            print('    oathtool -v {}-c{} -b --hotp {}  # ... with extra information'''.format(d, c, otp_secret_b32))
    elif otp_token['digits']==6 and otp_token['algorithm']=='sha1' and otp_token['period']==30:
        os.umask(0o077) # stoken does this too (security)
        with open(os.path.expanduser(args.dotfile), EXCL_WRITE) as dotfile:
            dotfile.write('version 1\n')
            dotfile.write('secret %s\n' % otp_secret_b32)
            dotfile.write('id %s\n' % otp_token['id'])
            dotfile.write('expiry %s\n' % otp_token['expiry'])
        print('Credential created and saved successfully: ' + dotfile.name)
        print('You will need the ID to register this credential: ' + otp_token['id'])
    else:
        p.error('Cannot currently save a token of this type (try -p to print)')

def check(p, args):
    if args.secret:
        d, secret = {'id': args.identity or 'Unknown'}, args.secret
    else:
        with open(args.dotfile, "r") as dotfile:
            d = dict( l.strip().split(None, 1) for l in dotfile )
        if 'version' not in d:
            p.error('%s does not specify version' % args.dotfile)
        elif d['version'] != '1':
            p.error("%s specifies version %r, rather than expected '1'" % (args.dotfile, d['version']))
        elif 'secret' not in d:
            p.error('%s does not specify secret' % args.dotfile)
        secret = d['secret']

    if d.get('id', 'Unknown') == 'Unknown':
        p.error("Token identity unknown; specify with -I/--identity")

    try:
        key = oath.google_authenticator.lenient_b32decode(secret)
    except Exception as e:
        p.error('error interpreting secret as base32: %s' % e)

    d.setdefault('period', 30)

    print("Checking token...")
    session = vp.requests.Session()
    for skew in (None, +d['period']//2, -d['period']//2, +d['period'], -d['period'], +d['period']*3//2, -d['period']*3//2):
        if skew is None:
            if vp.check_token(d, key, session):
                print("Token is valid and working.")
                break
        else:
            print("Trying %+d seconds timeskew..." % skew)
            if vp.check_token(d, key, session, timestamp=time.time()+skew):
                print("Token is valid and working, but we had to skew by %+d seconds (check your system time)\n" % skew)
                break
    else:
        print("WARNING: Something went wrong--the token could not be validated.\n",
              file=sys.stderr)

def uri(p, args):
    if args.secret:
        d, secret = {'id': args.identity or 'Unknown'}, args.secret
    else:
        if not os.path.exists(args.dotfile):
            p.error("File %s does not exist." % args.dotfile)
        with open(args.dotfile, "r") as dotfile:
            d = dict( l.strip().split(None, 1) for l in dotfile )
        if 'version' not in d:
            p.error('%s does not specify version' % args.dotfile)
        elif d['version'] != '1':
            p.error("%s specifies version %r, rather than expected '1'" % (args.dotfile, d['version']))
        elif 'secret' not in d:
            p.error('%s does not specify secret' % args.dotfile)
        secret = d['secret']

    try:
        key = oath.google_authenticator.lenient_b32decode(secret)
    except Exception as e:
        p.error('error interpreting secret as base32: %s' % e)
    if args.verbose:
        print('Token URI:\n    ', file=sys.stderr, end='')
    print(vp.generate_otp_uri(d, key, args.issuer))

def show(p, args):
    if args.secret:
        secret = args.secret
    else:
        with open(args.dotfile, "r") as dotfile:
            d = dict( l.strip().split(None, 1) for l in dotfile )
        if 'version' not in d:
            p.error('%s does not specify version' % args.dotfile)
        elif d['version'] != '1':
            p.error("%s specifies version %r, rather than expected '1'" % (args.dotfile, d['version']))
        elif 'secret' not in d:
            p.error('%s does not specify secret' % args.dotfile)
        secret = d.get('secret')
        if args.verbose:
            if 'id' in d: print('Token ID: %s' % d['id'], file=sys.stderr)
            if 'expiry' in d: print('Token expiration: %s' % d['expiry'], file=sys.stderr)
            sys.stderr.write('\n')

    try:
        key = oath._utils.tohex( oath.google_authenticator.lenient_b32decode(secret) )
    except Exception as e:
        p.error('error interpreting secret as base32: %s' % e)
    print(oath.totp(key))

def main():
    p = argparse.ArgumentParser()

    class UnsetDotfileAndStore(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            # We need to unset dotfile so that PathType() doesn't try to check for its existence/nonexistence
            setattr(namespace, 'dotfile', None)
            setattr(namespace, self.dest, True if not values else values[0] if len(values)==1 else values)

    sp = p.add_subparsers(dest='cmd')

    pprov = sp.add_parser('provision', help='Provision a new VIP Access credential')
    pprov.set_defaults(func=provision)
    m = pprov.add_mutually_exclusive_group()
    m.add_argument('-p', '--print', action=UnsetDotfileAndStore, nargs=0,
                   help="Print the new credential, but don't save it to a file")
    m.add_argument('-o', '--dotfile', type=PathType(type='file', exists=False), default=os.path.expanduser('~/.vipaccess'),
                   help="File in which to store the new credential (default ~/.vipaccess)")
    pprov.add_argument('-i', '--issuer', default="VIP Access", action='store',
                       help="Specify the issuer name to use (default: %(default)s)")
    pprov.add_argument('-t', '--token-model', default='SYMC', type=check_token_model,
                      help='VIP Access token model. Often SYMC/VSMT ("mobile" token, default) or '
                           'SYDC/VSST ("desktop" token). Some clients only accept one or the other. '
                           "Other more obscure token types also exist: "
                           "https://support.symantec.com/en_US/article.TECH239895.html")

    pcheck = sp.add_parser('check', help='Check if a VIP Access credential is working')
    m = pcheck.add_mutually_exclusive_group()
    m.add_argument('-f', '--dotfile', type=PathType(type='file', exists=True), default=os.path.expanduser('~/.vipaccess'),
                   help="File in which the credential is stored (default ~/.vipaccess)")
    m.add_argument('-s', '--secret', action=UnsetDotfileAndStore, nargs=1,
                   help="Specify the token secret to test (base32 encoded)")
    pcheck.add_argument('-I', '--identity',
                       help="Specify the ID of the token to test (normally starts with VS or SYMC)")
    pcheck.set_defaults(func=check)

    pshow = sp.add_parser('show', help="Show the current 6-digit token")
    m = pshow.add_mutually_exclusive_group()
    m.add_argument('-s', '--secret', action=UnsetDotfileAndStore, nargs=1,
                   help="Specify the token secret on the command line (base32 encoded)")
    m.add_argument('-f', '--dotfile', type=PathType(type='file', exists=True), default=os.path.expanduser('~/.vipaccess'),
                   help="File in which the credential is stored (default ~/.vipaccess)")
    pshow.add_argument('-v', '--verbose', action='store_true')
    pshow.set_defaults(func=show)

    puri = sp.add_parser('uri', help="Export the credential as a URI (otpauth://)")
    m = puri.add_mutually_exclusive_group()
    m.add_argument('-s', '--secret',  action=UnsetDotfileAndStore, nargs=1,
                   help="Specify the token secret on the command line (base32 encoded)")
    m.add_argument('-f', '--dotfile', type=PathType(type='file', exists=True), default=os.path.expanduser('~/.vipaccess'),
                   help="File in which the credential is stored (default ~/.vipaccess)")
    puri.add_argument('-i', '--issuer', default="Symantec", action='store',
                       help="Specify the issuer name to use (default: Symantec)")
    puri.add_argument('-I', '--identity', action='store',
                       help="Specify the ID of the token to use (required with --secret))")
    puri.add_argument('-v', '--verbose', action='store_true')
    puri.set_defaults(func=uri)

    pver = sp.add_parser('version', help='Show version of this program')
    pver.set_defaults(func=lambda p, args: print('{} {}'.format(p.prog, __version__), file=sys.stderr))

    p.set_default_subparser('show')
    args = p.parse_args()
    return args.func(p, args)

if __name__=='__main__':
    main()
