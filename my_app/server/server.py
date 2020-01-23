import ldap
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from my_app.chat import application


# from application import my_app

def get_ldap_connection():
    # ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, CACert)
    # ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
    conn = ldap.initialize(application.app.config['LDAP_PROVIDER_URL'])
    conn.start_tls_s()
    return conn


class Server:

    @staticmethod
    def verify_v2(path_cert, trusted):
        cert_file = open(path_cert)
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(data=cert_data, backend=default_backend())

        # chain contains the Let's Encrypt certificate
        chain_file = open(trusted)
        chain_data = chain_file.read()
        chain = x509.load_pem_x509_certificate(data=chain_data, backend=default_backend())

        public_key = chain.public_key()

        verifier = public_key.verifier(
            signature=cert.signature,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            algorithm=hashes.SHA256())
        verifier.update(cert.tbs_certificate_bytes)
        try:
            verifier.verify()
            return True
        except:
            return False

    @staticmethod
    def verify(path_cert):
        try:
            with open(path_cert, 'r') as cert_file:
                cert = cert_file.read()
            with open("/home/sartharion/Bureau/ca/cacert.pem", 'r') as root_cert_file:
                root_cert = root_cert_file.read()

            trusted_certs = (root_cert, root_cert)
            # verified = Server.verify_chain_of_trust(cert, trusted_certs)
            verified = Server.verify_v2(path_cert, "/home/sartharion/Bureau/ca/cacert.pem")

            if verified:
                return True
            else:
                return False
        except:
            return False

    @staticmethod
    def verify_chain_of_trust(cert_pem, trusted_cert_pems):

        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()

        for trusted_cert_pem in trusted_cert_pems:
            trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
            store.add_cert(trusted_cert)

        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(store, certificate)

        # Returns None if certificate can be validated
        result = store_ctx.verify_certificate()

        if result is None:
            return True
        else:
            return False

    @staticmethod
    def verify_ldap_cert(username):
        conn = get_ldap_connection()
        conn.simple_bind_s('cn=admin,dc=projet,dc=com', 'Inchalah1.')
        path = conn.search_s('ou=people,dc=projet,dc=com', ldap.SCOPE_SUBTREE,
                             '(&(objectclass=inetOrgPerson)(cn=' + username + '))',
                             ['description'])
        try:
            cert = path[0][1]['description'][0].decode()
        except:
            cert = ''
        path = "/home/sartharion/Bureau/chat-room/my_app/client/clients_crt/crt" + username + ".pem"
        verified = Server.verify(path)
        # if not verified:
        #     raise ValueError('Certificate Denied')
