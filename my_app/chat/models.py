import ldap
from flask_login import UserMixin
from ldap import modlist
from my_app import db, app


def get_ldap_connection():
    ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
    conn = ldap.initialize(app.config['LDAP_PROVIDER_URL'])
    conn.start_tls_s()
    return conn


# user mixing gestion user
class User(UserMixin, db.Model):
    """ User model """

    # __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    # password = db.Column(db.String(), nullable=False)

    @staticmethod
    def try_register(username, password, certificate):
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
                "description": [certificate.encode('utf-8')]
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
