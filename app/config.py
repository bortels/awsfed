# You should modify this for your own use.
# In particular, set the FQDN to your domain name, and
# pick and set a secure SECRET_KEY. If you are going
# to run HA, you will want to modify the SQLALCHEMY
# variables to point to your shared server rather than
# SQLite3.

import os

ENV = os.environ.get("ENV", "dev")
SECRET_KEY = 'top-secret'
SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'
SQLALCHEMY_TRACK_MODIFICATIONS = False
PERMANENT_SESSION_LIFETIME = 60 * 60 * 20
BOOTSTRAP_CDN_FORCE_SSL = True
BOOTSTRAP_SERVE_LOCAL = True
SCHEME = "https"
FQDN = f'fed-{ENV}.bortels.us'
URL = f'{SCHEME}://{FQDN}'
