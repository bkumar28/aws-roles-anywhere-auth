from datetime import datetime, timedelta
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def mk_ca_issuer(common_name="Roles Anywhere ROOT CA"):
    """
    Our default CA issuer name.
    """
    issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Rockville"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Cloudbolt Software"),
            ])

    return issuer

   
def generate_self_signed_certificate(to_time, from_time, cert_dir):
    """
    Generates self signed certificate (X509 Root CA)
    :param to_time: not available certificate after the time
    :param from_time: not available certificate before the time
    :param cert_dir: save root cert and key in dir
    :returns: generated private key and certificate pair
    """
    # generate rsa private key
    private_key = rsa.generate_private_key(public_exponent=65537,  key_size=2048)
   
    # subject and issuer are always the same.
    subject = mk_ca_issuer()
    issuer = subject
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    
    
    subject_ext = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())

    key_usage_ext = x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=True,
                                key_agreement=False, content_commitment=False, data_encipherment=False,
                                crl_sign=True, encipher_only=False, decipher_only=False)

    authority_key_ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key())

    # Used to build the root CA certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(from_time)
        .not_valid_after(to_time)
        .add_extension(basic_contraints, True)
        .add_extension(key_usage_ext, True)
        .add_extension(subject_ext, False)
        .add_extension(authority_key_ext, False)
        .sign(private_key, hashes.SHA256())
    )
    
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
    
    with open(cert_dir+'root-cert.pem', 'w') as f:
        f.write(cert_pem)

    print("*****************Root CA**********************")
    print(cert_pem)

    private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8")
    
    with open(cert_dir+'root-key.pem', 'w') as f:
        f.write(private_key_pem)

    print("*****************Root CA Private Key**********************")
    print(private_key_pem)

    return {'certificate': cert_pem, 'private_key': private_key_pem}


def generate_client_certificate(root_cert, root_private_key, from_time, to_time, cert_dir):
    """
    Generate Client Certificate
    :param root_cert: Root CA
    :param root_private_key: private key of Root CA
    :param to_time: not available certificate after the time
    :param from_time: not available certificate before the time
    :param cert_dir: save client cert, chain and key in dir
    :returns: generated private key and certificate pair
    """

    if not isinstance(root_private_key, rsa.RSAPrivateKey):
        root_private_key = serialization.load_pem_private_key(root_private_key.encode("utf-8"), None)

    if not isinstance(root_cert, x509.CertificateBuilder):
        root_cert = x509.load_pem_x509_certificate(root_cert.encode("utf-8"))

    common_name="Roles Anywhere Client"

    # subject and issuer are always the same.
    subject = mk_ca_issuer(common_name)

    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=False, path_length=None)

    key_usage_ext = x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                                key_agreement=False, content_commitment=False, data_encipherment=True,
                                crl_sign=False, encipher_only=False, decipher_only=False)

    authority_key_ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key())

    # Used to build client csr
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(basic_contraints, True)
        .add_extension(key_usage_ext, True)
        .add_extension(authority_key_ext, False)
        .sign(root_private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    with open(cert_dir+'client-csr.pem', 'w') as f:
        f.write(csr_pem)

    print("******************Client Certificate Chain**********************")
    print(csr_pem)

    # Used to build client certificate
    builder = x509.CertificateBuilder(
        issuer_name=root_cert.issuer,
        subject_name=csr.subject,
        public_key=csr.public_key(),
        not_valid_before=from_time,
        not_valid_after=to_time,
        extensions=csr.extensions,
        serial_number=root_cert.serial_number,
    )

    certificate = builder.sign(
            private_key=root_private_key, algorithm=hashes.SHA256()
        ).public_bytes(serialization.Encoding.PEM).decode("utf-8")

    with open(cert_dir+'client-cert.pem', 'w') as f:
        f.write(certificate)

    print("*******************Client Certificate***********************")
    print(certificate)

    private_key_pem = root_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

    with open(cert_dir+'client-key.pem', 'w') as f:
        f.write(private_key_pem)

    print("*****************Client Private Key**********************")
    print(private_key_pem)

    return {'client_cerfiticate':certificate,'client_cerfiticate_chain':csr_pem, "private_key": private_key_pem}


if __name__ == "__main__":
    cert_dir = os.path.abspath(os.getcwd()) + "/certificates_data/"
    
    if not os.path.isdir(cert_dir):
        os.makedirs(cert_dir) # create dir if not exist
    
    from_time = datetime.utcnow()
    to_time = from_time + timedelta(days=10*365)

    x509_data = generate_self_signed_certificate(to_time, from_time, cert_dir)

    client_ca_data = generate_client_certificate(x509_data['certificate'], 
                                        x509_data['private_key'], from_time, to_time, cert_dir)
