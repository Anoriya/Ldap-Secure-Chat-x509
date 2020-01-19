import ldap
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
            attributes = {
                "objectClass": [b"inetOrgPerson"],
                "sn": [username.encode('utf-8')],
                "cn": [username.encode('utf-8')],
                "userPassword": [password.encode('utf-8')],
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
