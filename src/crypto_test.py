import sys
import os
import behave
import pyotp


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


env = os.environ
if not (api_key := env.get('API_KEY_KRAKEN')):
    msg = 'API_KEY_KRAKEN env variable not set'
    eprint(msg)
    sys.exit(1)

if not (api_sec := env.get('API_SEC_KRAKEN')):
    msg = 'API_SEC_KRAKEN env variable not set'
    eprint(msg)
    sys.exit(1)

if not (totp_sec := env.get('TOTP2_SEC_KRAKEN')):
    msg = 'TOTP_SEC_KRAKEN env variable not set'
    eprint(msg)
    sys.exit(1)

totp = pyotp.TOTP(totp_sec)

print(api_key)
print(api_sec)
print(totp.now())






