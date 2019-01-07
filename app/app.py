# Fed
#
# A portal for federated access to AWS console and resources
#
#

# so many imports
import os
import base64
from io import BytesIO
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    session,
    abort,
    request,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.contrib.fixers import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
import onetimepass
import pyqrcode
import boto3
from botocore.exceptions import ClientError
import json
import urllib.parse
import requests
import safe
from datetime import datetime
import pprint
import logging
import arrow
from apscheduler.schedulers.background import BackgroundScheduler
import time
import re


# from logging.handlers import RotatingFileHandler
# import yaml

# create application instance
app = Flask(__name__, static_url_path="/static")
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config.from_object("config")
if app.config["ENV"] == "dev":
    debug = True
else:
    debug = False

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)

awsconfig = {"users": {}, "roles": {}}


# from https://blog.hartwork.org/posts/flask-behind-a-reverse-proxy-actual-client-ips/
def fix_werkzeug_logging():
    from werkzeug.serving import WSGIRequestHandler

    def address_string(self):
        forwarded_for = self.headers.get(
            'X-Forwarded-For', '').split(',')

        if forwarded_for and forwarded_for[0]:
            return forwarded_for[0]
        else:
            return self.client_address[0]

    WSGIRequestHandler.address_string = address_string


# Print timestamped line to log
def plog(text):
    print(f"{ arrow.now().isoformat() } { text }")


# Modify the description field of an AWS Security Group Rule targeted by CIDR
def modify_description(account, cidr, description):
    accountinfo = awsconfig["accounts"][account]
    session = boto3.Session(accountinfo["id"], accountinfo["secret"])
    security_groups = accountinfo["security_groups"]
    for sg in security_groups:
        sgid = sg["sgid"]
        region = sg["region_name"]
        ec2 = session.client("ec2", region_name=region)
        try:
            ec2.update_security_group_rule_descriptions_ingress(
                GroupId=sgid,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": cidr, "Description": description}],
                    }
                ],
            )
        except ClientError as e:
            plog(f"exception updating description {description} in {sgid} : {e.response['Error']['Code']}")


# Add user and their CIDR to the security group
def authorize_ssh(account, cidr, username):
    if "ssh-" in account:
        plog(f"Adding {username} {cidr} to {account}")
        description = (
            "fed-" + username + ":" + arrow.utcnow().shift(hours=20).isoformat()
        )
        accountinfo = awsconfig["accounts"].get(account)
        if accountinfo is None:
            plog(f'account {account} not found, skipping')
            return
        session = boto3.Session(accountinfo["id"], accountinfo["secret"])
        security_groups = accountinfo["security_groups"]
        for sg in security_groups:
            sgid = sg["sgid"]
            region = sg["region_name"]
            ec2 = session.client("ec2", region_name=region)
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sgid,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": cidr, "Description": description}],
                        }
                    ],
                )
            except Exception:
                modify_description(account, cidr, description)


# Search Security groups removing rule allowing a specific CIDR
def revoke_ssh(account, cidr):
    if "ssh-" in account:
        accountinfo = awsconfig["accounts"][account]
        session = boto3.Session(accountinfo["id"], accountinfo["secret"])
        security_groups = accountinfo["security_groups"]
        for sg in security_groups:
            try:
                sgid = sg["sgid"]
                region = sg["region_name"]
                ec2 = session.client("ec2", region_name=region)
                ec2.revoke_security_group_ingress(
                    GroupId=sgid,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": cidr}],
                        }
                    ],
                )
            except ClientError as e:
                plog(f"Failed to remove {cidr} from {sgid} in {account} {region} : {e.response['Error']['Code']}")


# Scan a security group, looking at timestamps on rules, and expire old rules
def expire_sg(account):
    if "ssh-" in account:
        accountinfo = awsconfig["accounts"][account]
        session = boto3.Session(accountinfo["id"], accountinfo["secret"])
        security_groups = accountinfo["security_groups"]
        for sg in security_groups:
            sgid = sg["sgid"]
            region = sg["region_name"]
            # plog(f"Trying to expire {sgid} {region}")
            ec2 = session.client("ec2", region_name=region)
            sginfo = ec2.describe_security_groups(GroupIds=[sgid])["SecurityGroups"][0]
            for ipp in sginfo["IpPermissions"]:
                for rule in ipp["IpRanges"]:
                    cidr = rule["CidrIp"]
                    description = rule.get("Description")
                    r = description.split(":", 1)
                    if len(r) > 1:
                        user, expires = r
                        if "fed-" in user:
                            e = arrow.get(expires)
                            now = arrow.utcnow()
                            # plog(f'{user} expires {e.humanize()}')
                            if e < now:
                                plog(f"expiring {user}")
                                revoke_ssh(account, cidr)
                    # else:
                    #    plog(f'{r[0]} is ignored')


# add user to SG for every "ssh-" account
def update_security_groups(cidr, user):
    accounts = get_accounts(user)
    for account in accounts:
        if "ssh-" in account:
            authorize_ssh(account, cidr, user)


# Call expire_sg for all relevant accounts, with a delay so we don't kill the API
def expire_all_sgs():
    accounts = awsconfig.get("accounts")
    if accounts:
        # plog("Expiring Security Groups")
        for account in accounts:
            if "ssh-" in account:
                time.sleep(5)
                expire_sg(account)


# Get all of the roles for a user
def get_groups(user):
    return awsconfig["users"].get(user, [])


# Return a list of accounts available to a given user
def get_accounts(user):
    out = []
    grouplist = awsconfig["users"].get(user, [])
    for group in grouplist:
        roles = awsconfig["roles"].get(group, [])
        for role in roles:
            out.append(role)
    return list(sorted(set(out)))


# Return the description field for a given account
def get_account_description(name):
    accountinfo = awsconfig["accounts"].get(name)
    if accountinfo is None:
        return f'account_{name}_not_found'
    return accountinfo.get("description", name)


# Export for use in templates
app.jinja_env.globals.update(get_accounts=get_accounts)
app.jinja_env.globals.update(get_account_description=get_account_description)


# return session creds for a given account, user, and optional policy
def getsessioncreds(account, user, policy):
    if not policy:
        policy = '{"Statement":[{"Resource":"*","Action":"*","Effect":"Allow"}],"Version":"2012-10-17"}'
    accountinfo = awsconfig["accounts"][account]
    session = boto3.Session(accountinfo["id"], accountinfo["secret"])
    sts = session.client("sts")
    fedname = "fed-" + user
    fedname = re.sub(r"[^\w+=,.@-]", '', fedname)
    usersession = sts.get_federation_token(Name=fedname, Policy=policy)
    creds = usersession.get("Credentials")
    return json.dumps(
        {
            "sessionId": creds["AccessKeyId"],
            "sessionKey": creds["SecretAccessKey"],
            "sessionToken": creds["SessionToken"],
        }
    )


# return session creds environment return for scripts
def getsessioncredsenv(account, user, policy):
    if not policy:
        policy = '{"Statement":[{"Resource":"*","Action":"*","Effect":"Allow"}],"Version":"2012-10-17"}'
    accountinfo = awsconfig["accounts"][account]
    session = boto3.Session(accountinfo["id"], accountinfo["secret"])
    sts = session.client("sts")
    usersession = sts.get_federation_token(Name="fsc-" + user, Policy=policy)
    creds = usersession.get("Credentials")
    return "\n".join(
        [
            "export AWS_ACCESS_KEY_ID=" + creds["AccessKeyId"],
            "export AWS_SECRET_ACCESS_KEY=" + creds["SecretAccessKey"],
            "export AWS_SESSION_TOKEN=" + creds["SessionToken"],
        ]
    )


# Get a URL for signin for a given account/user/policy
def getfedlink(account, user, policy):
    session_json = getsessioncreds(account, user, policy)
    issuer_url = app.config["SCHEME"] + "://" + app.config["FQDN"]
    console_url = "https://console.aws.amazon.com/ec2"
    signin_url = "https://signin.aws.amazon.com/federation"
    get_signin_token_url = (
        signin_url
        + "?Action=getSigninToken&SessionType=json&Session="
        + urllib.parse.quote_plus(session_json)
    )
    returned_content = requests.get(get_signin_token_url)
    signin_token = returned_content.json().get("SigninToken")
    signin_token_param = "&SigninToken=" + urllib.parse.quote_plus(signin_token)
    issuer_param = "&Issuer=" + urllib.parse.quote_plus(issuer_url)
    destination_param = "&Destination=" + urllib.parse.quote_plus(console_url)
    login_url = (
        signin_url
        + "?Action=login"
        + signin_token_param
        + issuer_param
        + destination_param
    )
    # @c.out("status" => "303", "Connection" => "close", "Content-Length" => 1, "Location" => login_url) {' '}
    return login_url


class User(UserMixin, db.Model):
    """User model."""

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    fullname = db.Column(db.String(64))
    email = db.Column(db.String(64))
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode("utf-8")

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return "otpauth://totp/awsfed:{0}?secret={1}&issuer=AWSFed".format(
            self.username, self.otp_secret
        )

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret, window=1)

    # @property  <-- This doesn't work. I don't know why. Is a puzzlement.
    def is_admin(self):
        return "fedadmin" in get_groups(self.username)

    is_admin = property(is_admin)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """Registration form."""

    username = StringField("Username", validators=[DataRequired(), Length(1, 24)])
    fullname = StringField("Full Name", validators=[DataRequired(), Length(1, 64)])
    email = StringField("Email Address", validators=[DataRequired(), Length(1, 64)])
    password = PasswordField("Password", validators=[DataRequired()])
    password_again = PasswordField(
        "Password again", validators=[DataRequired(), EqualTo("password")]
    )
    token = PasswordField(
        "Registration secret from the wiki (if you don't have wiki access, talk to someone!)", validators=[DataRequired()]
    )
    submit = SubmitField("Register")

    def validate_password(self, field):
        c = safe.check(field.data)
        if bool(c):
            return True
        self.password.errors.append(str(c))
        return False


class LoginForm(FlaskForm):
    """Login form."""

    username = StringField("Username", validators=[DataRequired(), Length(1, 64)])
    password = PasswordField("Password", validators=[DataRequired()])
    token = StringField("Token", validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField("Login")


# inject debug flag into all templates
@app.context_processor
def inject_debug():
    return dict(debug=app.debug)


@app.route("/")
def index():
    return render_template("index.html", request=request, url=app.config["URL"])


@app.route('/robots.txt')
def robots():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'robots.txt', mimetype='text/plain')


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/apple-touch-icon.png')
def appletouchicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'apple-touch-icon-180x180.png', mimetype='image/png')


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/time")
def get_time():
    """Get current server time - used for troubleshooting, MFA can be picky"""
    return str(datetime.now().timestamp())


# new user registration
@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for("index", _external=True, _scheme=app.config["SCHEME"]))
    form = RegisterForm()
    if form.validate_on_submit():
        token = form.token.data
        if token != "elderberries":
            plog(f"Bad registration secret input {token}")
            flash("Unauthorized Registration Denied. Go read the wiki to get the right secret.")
            return redirect(
                url_for("register", _external=True, _scheme=app.config["SCHEME"])
            )
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            plog(f'Username already exists: { form.username.data }')
            flash("Username already exists.")
            return redirect(
                url_for("register", _external=True, _scheme=app.config["SCHEME"])
            )
        # add new user to the database
        user = User(
            username=form.username.data,
            password=form.password.data,
            fullname=form.fullname.data,
            email=form.email.data,
        )
        db.session.add(user)
        db.session.commit()

        # redirect to the two-factor auth page, passing username in session
        session["username"] = user.username
        plog(url_for("two_factor_setup", _external=True, _scheme=app.config["SCHEME"]))
        return redirect(
            url_for("two_factor_setup", _external=True, _scheme=app.config["SCHEME"])
        )
    return render_template("register.html", form=form)


# Display page with the QA code as part of registration
@app.route("/twofactor")
def two_factor_setup():
    if "username" not in session:
        return redirect(url_for("index", _external=True, _scheme=app.config["SCHEME"]))
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        return redirect(url_for("index", _external=True, _scheme=app.config["SCHEME"]))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return (
        render_template("two-factor-setup.html"),
        200,
        {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# Display a QR Code for the User's MFA
@app.route("/qrcode")
def qrcode():
    if "username" not in session:
        abort(404)
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session["username"]

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return (
        stream.getvalue(),
        200,
        {
            "Content-Type": "image/svg+xml",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login route."""
    remote_ip = request.environ.get("HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR"))

    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for("index", _external=True, _scheme=app.config["SCHEME"]))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            plog(
                "LOGIN "
                + " ip:"
                + str(remote_ip)
                + " user:"
                + str(user.username)
                + " pass:"
                + str(user.verify_password(form.password.data))
                + " mfa:"
                + str(user.verify_totp(form.token.data))
            )
        if (
            user is None
            or not user.verify_password(form.password.data)
            or not user.verify_totp(form.token.data)
        ):
            flash("Invalid username, password or token.")
            return redirect(
                url_for("login", _external=True, _scheme=app.config["SCHEME"])
            )

        # log user in
        login_user(user)
        # Update Security Groups
        update_security_groups(remote_ip + "/32", user.username)
        flash("You are now logged in!")
        return redirect(url_for("index", _external=True, _scheme=app.config["SCHEME"]))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    """User logout route."""
    try:
        if current_user.is_authenticated:
            user = current_user.username
            remote_ip = request.environ.get(
                "HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR")
            )
            plog(f"LOGOUT {user} {remote_ip}")
            accounts = get_accounts(user)
            for account in accounts:
                revoke_ssh(account, remote_ip + "/32")
            logout_user()
        return redirect(url_for("index", _external=True, _scheme=app.config["SCHEME"]))
    except Exception as e:
        plog(f'logout issue for {user} {remote_ip} : {e.message}')
        logout_user()
        return redirect(url_for("index", _external=True, _scheme=app.config["SCHEME"]))


# This handles the actual Console URIs the user clicks on
@app.route("/aws/<accountname>")
def aws(accountname):
    if current_user.is_authenticated:
        user = current_user.username
        if accountname in get_accounts(user):
            url = getfedlink(accountname, user, None)
            return redirect(url, code=303)
        else:
            abort(404)
    else:
        flash("session expired. Please log in again.")
        return redirect(url_for("login", _external=True, _scheme=app.config["SCHEME"]))


# This handles the actual Console URIs the user clicks on
@app.route("/awscreds/<accountname>")
def awscreds(accountname):
    if current_user.is_authenticated:
        user = current_user.username
        if accountname in get_accounts(user):
            creds = getsessioncredsenv(accountname, user, None)
            return render_template("awscreds.html", accountname=accountname, creds=creds, awsconfig=awsconfig)
        else:
            abort(404)
    else:
        flash("session expired. Please log in again.")
        return redirect(url_for("login", _external=True, _scheme=app.config["SCHEME"]))


# Configuration upload.
# If the config is blank, accept the first config uploaded.
# Thereafter, accept uploads if the secret matches.
@app.route("/configure", methods=["POST"])
def configure():
    global awsconfig
    secret1 = awsconfig.get("secret")
    newconfig = request.get_json()
    if secret1 is None:
        awsconfig = newconfig
        plog("New configuration loaded")
        return "OK"
    secret1 = awsconfig.get("secret")
    secret2 = newconfig.get("secret")
    if secret2 is None:
        return "NO secret is not present"
    if secret1 == secret2:
        plog("Updated configuration loaded.")
        awsconfig = newconfig
        return "OK"
    return "NO"


@app.route("/admin")
def admin():
    if current_user.is_authenticated:
        if "master" in get_groups(current_user.username):
            users = User.query.all()
            return render_template("admin.html", users=users, awsconfig=awsconfig)
    abort(403)


@app.route("/delete_user", methods=["POST"])
def delete_user():
    if current_user.is_authenticated:
        if "master" in get_groups(current_user.username):
            user_to_delete = request.form["userid"]
            flash(f'Deleted user "{user_to_delete}""')
            User.query.filter(User.username == user_to_delete).delete()
            db.session.commit()
            return redirect(
                url_for("admin", _external=True, _scheme=app.config["SCHEME"])
            )
    abort(403)


# Drop a copy of the request to logging
@app.route("/log")
def log_callback():
    """Dump the request object to stdout for debugging"""
    plog(pprint.pformat(request.__dict__, depth=5))
    return "OK"


# test the key for a given accoubt to confirm functionality
# this is called by the key rotation external script
@app.route("/testkey/<keyname>")
def testkey(keyname):
    try:
        accountinfo = awsconfig["accounts"][keyname]
        session = boto3.Session(accountinfo["id"], accountinfo["secret"])
        sts = session.client("sts")
        usersession = sts.get_caller_identity()
        return usersession['Arn']
    except Exception as e:
        abort(404)


# test all keys
# Should probably hardcode this to specific IPs
@app.route("/testaccesskeys")
def testkeys():
    success = 0
    fail = 0
    bad = []
    for keyname in awsconfig["accounts"]:
        try:
            accountinfo = awsconfig["accounts"][keyname]
            session = boto3.Session(accountinfo["id"], accountinfo["secret"])
            sts = session.client("sts")
            sts.get_caller_identity()
            success = success + 1
        except Exception as e:
            fail = fail + 1
            bad.append(keyname)
    return json.dumps(
        {
            "success": success,
            "fail": fail,
            "bad": bad
        }
    )


# Custom 404 handler because we have needs.
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    # remote_ip = request.environ.get("HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR"))
    # plog(f'404 from {remote_ip}')  # log the actual source IP because logging gets the ALB internal IP.
    time.sleep(5)  # tarpit so scanners have a bad day
    return render_template('404.html'), 404


# Add headers to all outgoing responses to deal with common security concerns
@app.after_request
def apply_caching(response):
    response.headers['server'] = "Zanzibar"  # Let's not tell people what we run
    response.headers["X-Frame-Options"] = "deny"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000 ; includeSubDomains ; preload"
    response.headers["Content-Security-Policy"] = ("default-src 'self' "
                                                   "'sha256-JMZOU8BcaItzGyYxtaMNNNUOnQq9LQbKEaXfw/WUkfo=' "
                                                   "'sha256-RQr56zHCuub99h6rKodb5eik75gEYMw/OD6cYTtCpOM=' "
                                                   "cdnjs.cloudflare.com "
                                                   "; object-src " + app.config["URL"]
                                                   # " ; script-src 'strict-dynamic' "
                                                   )
    return response


if __name__ == "__main__":
    # create database tables if they don't exist yet
    db.create_all()

    # app.logger.disabled = True
    # log = logging.getLogger("werkzeug")
    # log.disabled = True

    class Stoplogs(logging.Filter):
        """Stop logging messages from health checks"""

        def __init__(self, name=None):
            pass

        def filter(self, rec):
            # Stop logging of ALBs doing health checks
            logblacklist = ["10.30.253.123", "10.30.253.29", "10.30.254.70",
                            "10.30.253.121", "10.30.253.23", "10.30.254.130"]
            if '"GET / HTTP/1.1" 200 -' in rec.msg:
                for ip in logblacklist:
                    if ip in rec.msg:
                        return False
            return True

    log = logging.getLogger("werkzeug")
    stoplogs = Stoplogs()
    log.addFilter(stoplogs)

    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(func=expire_all_sgs, trigger="interval", seconds=300)
    scheduler.start()

    if debug:
        app.run(host="0.0.0.0", debug=True, threaded=True)
    else:
        app.run(host="0.0.0.0", debug=False, use_evalex=False, threaded=True)
