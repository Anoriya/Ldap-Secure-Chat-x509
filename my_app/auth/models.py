import ldap
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask_login._compat import unicode
from flask_wtf import Form
from ldap import modlist
from wtforms import TextField, PasswordField
from wtforms.validators import InputRequired

from my_app import db, app

CACert = '/etc/ssl/certs/cacert.pem'


def get_ldap_connection():
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, CACert)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
    conn = ldap.initialize(app.config['LDAP_PROVIDER_URL'])
    conn.start_tls_s()
    return conn


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))

    def __init__(self, username, password):
        self.username = username

    @staticmethod
    def generate_rsa_key(key_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
            ))
            return private_key

    @staticmethod
    def generate_certificate():
        private_key = User.generate_rsa_key("/etc/priv_key" + User.query.all().count() + ".pem")
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(u"mysite.com"),
                x509.DNSName(u"www.mysite.com"),
                x509.DNSName(u"subdomain.mysite.com"),
            ]),
            critical=False,
            # Sign the CSR with our private key.
        ).sign(private_key, hashes.SHA256(), default_backend())
        # Saving
        with open("/etc/csr" + User.query.all().count() + ".pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        return csr

    @staticmethod
    def get_users(self):
        conn = get_ldap_connection()
        try:
            conn.simple_bind_s('cn=admin,dc=projet,dc=com', 'Inchalah1.')
            result = conn.search_s('ou=people,dc=projet,dc=com', ldap.SCOPE_SUBTREE,
                                   '(&(objectclass=inetOrgPerson))',
                                   ['*'])
            conn.unbind_s()
            return result
        except ldap.LDAPError:
            conn.unbind_s()
            return 'authentication error'

    @staticmethod
    def try_register(username, password):
        conn = get_ldap_connection()
        conn.simple_bind_s('cn=admin,dc=projet,dc=com', 'Inchalah1.')
        # Search for existing user otherwise raise error
        result = conn.search_s('ou=people,dc=projet,dc=com', ldap.SCOPE_SUBTREE,
                               '(&(objectclass=inetOrgPerson)(sn=' + username + '))',
                               ['sn'])
        if result:
            raise ValueError('User already exist')
        # If user does not exist add it to ldap server
        else:
            User.generate_certificate()  # TO DO : RACHED BOUCHOUCHA
            cert = User.sign_certificate()  # TO DO : RACHED BOUCHOUCHA
            attributes = {
                "objectClass": [b"inetOrgPerson"],
                "sn": [username.encode('utf-8')],
                "cn": [username.encode('utf-8')],
                "userPassword": [password.encode('utf-8')],
                "cert_path": [cert.encode('utf-8')]
            }
            ldif = modlist.addModlist(attributes)
            res = conn.add_s(
                'cn=' + username + ',ou=people,dc=projet,dc=com', ldif
            )
            conn.unbind_s()
            if res:
                return True
            else:
                return False

    @staticmethod
    def try_login(username, password):
        conn = get_ldap_connection()
        conn.simple_bind_s(
            'cn=%s,ou=people,dc=projet,dc=com' % username,
            password
        )

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)


class LoginForm(Form):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])
