import json

from ldap3 import Server, Connection, ALL, MODIFY_REPLACE


class LdapFunctions:
    def __init__(self):

        self.server_ip = '54.36.182.216'
        self.ldap_username = 'cn=admin,dc=insat,dc=chat,dc=com'
        self.ldap_password = 'azerty123'
        self.ldap_server = Server(self.server_ip, get_info=ALL)
        self.conn = Connection(self.server_ip, self.ldap_username, self.ldap_password, auto_bind=True)

    def connect(self):
        self.conn.bind()

    def disconnect(self):
        self.conn.unbind()

    def get_users(self):
        try:
            self.connect()
            self.conn.search('ou=People,dc=insat,dc=chat,dc=com', '(&(objectclass=inetOrgPerson))', attributes=['*'])
            users = []
            for entry in self.conn.entries:
                users.append(json.loads(entry.entry_to_json()))

            self.disconnect()
            return users
        except ldap3.LDAPError:
            self.conn.unbind()
            return 'authentication error'

    def get_user(self, username=None):
        if (username == None):
            return {}
        try:
            self.connect()
            # attributes=['cn', 'sn']
            self.conn.search('ou=People,dc=insat,dc=chat,dc=com', '(&(objectclass=inetOrgPerson)(sn=' + username + '))',
                             attributes=['*'])
            if (not self.conn.entries):
                return "User doesn't exist"
            else:
                user = json.loads(self.conn.entries[0].entry_to_json())

            self.disconnect()
            return user
        except ldap3.LDAPError:
            self.conn.unbind()
            return 'authentication error'

    def add_user(self):
        try:
            self.connect()
            user = json.loads(request.data)
            # print(user)

            # before adding i need to select by username to make sure it's unique
            username = user['sn']
            self.conn.search('ou=People,dc=insat,dc=chat,dc=com', '(&(objectclass=inetOrgPerson)(sn=' + username + '))',
                             attributes=['sn'])
            if (self.conn.entries):
                self.conn.unbind()
                return "User already exists"
            else:
                res = self.conn.add(
                    'cn=' + user['sn'] + ',ou=People,dc=insat,dc=chat,dc=com',
                    attributes={
                        "objectClass": "inetOrgPerson",
                        "sn": user['sn'],
                        "uid": user['uid'],
                        "givenName": user['givenName'],
                        "displayName": user['displayName'],
                        "userPassword": user['userPassword'],
                        "userPKCS12": user['userPKCS12'],
                    },
                )

                self.conn.unbind()
                if (res):
                    return 'User added succefully'
                else:
                    return 'User already exists'

        except ldap3.LDAPError:
            self.conn.unbind()
            return 'Authentication error'

    def modify_user(self, username):
        try:
            self.connect()
            user = json.loads(request.data)
            # print(user)

            edits = {}
            if 'displayName' in user:
                edits['displayName'] = [(MODIFY_REPLACE, user['displayName'])]
            if 'givenName' in user:
                edits['givenName'] = [(MODIFY_REPLACE, user['givenName'])]
            if 'uid' in user:
                edits['uid'] = [(MODIFY_REPLACE, user['uid'])]
            if 'userPKCS12' in user:
                edits['userPKCS12'] = [(MODIFY_REPLACE, user['userPKCS12'])]
            if 'userPassword' in user:
                edits['userPassword'] = [(MODIFY_REPLACE, user['userPassword'])]

            res = self.conn.modify(
                dn='cn=' + username + ',ou=People,dc=insat,dc=chat,dc=com',
                changes=edits,
            )

            self.conn.unbind()
            if (res):
                return 'User edited succefully'
            else:
                return 'An error has occured'

        except ldap3.LDAPError:
            self.conn.unbind()
            return 'Authentication error'

    def delete_user(self, username=None):
        if (username == None):
            return 'An error has occured'
        try:
            self.connect()
            res = self.conn.delete('cn=' + username + ',ou=People,dc=insat,dc=chat,dc=com')
            self.conn.unbind()
            if (res):
                return 'User deleted succefully'
            else:
                return 'An error has occured'
        except ldap3.LDAPError:
            self.conn.unbind()
            return 'Authentication error'
