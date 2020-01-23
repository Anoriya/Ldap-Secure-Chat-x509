import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def signRequestCSR(username):
    pem_csr = open("/home/sartharion/Bureau/v2/my_app/client/clients_csr/csr" + username + ".pem", 'rb').read()
    try:
        csr = x509.load_pem_x509_csr(pem_csr, default_backend())
    except Exception:
        raise Exception("CSR presented is not valid.")
    caPem = open("/home/sartharion/Bureau/ca/cacert.pem", 'rb').read()
    ca = x509.load_pem_x509_certificate(caPem, default_backend())
    # load key ca
    caKeyPem = open("/home/sartharion/Bureau/ca/cakey.pem", 'rb').read()
    caKey = serialization.load_pem_private_key(caKeyPem, password=None, backend=default_backend())

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca.subject)
    builder = builder.not_valid_before(datetime.datetime.now() - datetime.timedelta(1))
    builder = builder.not_valid_after(datetime.datetime.now() + datetime.timedelta(360))
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number((int(uuid.uuid4())))

    certificate = builder.sign(
        private_key=caKey,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    with open("/home/sartharion/Bureau/v2/my_app/client/clients_crt/crt" + username + ".pem", 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
