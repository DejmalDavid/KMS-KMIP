#!/usr/bin/env python3

#original source is from PyKMIP https://github.com/OpenKMIP/PyKMIP/blob/master/bin/create_certificates.py
#edited for purpose of Master Thesis of David Dejmal 2021

#Create 3 key-pairs Root CA, Server (kms-server), Test User (localhost test usage of kms-server)

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime


def create_rsa_private_key(key_size=2048, public_exponent=65537):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=backends.default_backend()
    )
    return private_key


def create_self_signed_certificate(subject_name, private_key, days_valid=365):
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Test, Inc."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    ).sign(private_key, hashes.SHA256(), backends.default_backend())

    return certificate


def create_certificate(subject_name,
                       private_key,
                       signing_certificate,
                       signing_key,
                       days_valid=365,
                       client_auth=False):
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Test, Inc."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)
    ])
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        signing_certificate.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    )

    if client_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        )

    certificate = builder.sign(
        signing_key,
        hashes.SHA256(),
        backends.default_backend()
    )
    return certificate


def main():
    root_key = create_rsa_private_key()
    root_certificate = create_self_signed_certificate(
        u"Root CA",
        root_key
    )

    server_key = create_rsa_private_key()
    server_certificate = create_certificate(
        u"Server Certificate",
        server_key,
        root_certificate,
        root_key
    )

    test_user_client_key = create_rsa_private_key()
    test_user_client_certificate = create_certificate(
        u"Test User",
        test_user_client_key,
        root_certificate,
        root_key,
        client_auth=True
    )

    
    with open("/etc/pykmip/ssl/root_key.pem", "wb") as f:
        f.write(root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("/etc/pykmip/ssl/root_cert.pem", "wb") as f:
        f.write(
            root_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
    with open("/etc/pykmip/ssl/server_key.pem", "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("/etc/pykmip/ssl/server_cert.pem", "wb") as f:
        f.write(
            server_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )
    with open("/etc/pykmip/ssl/client_key_test_user.pem", "wb") as f:
        f.write(test_user_client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("/etc/pykmip/ssl/client_cert_test_user.pem", "wb") as f:
        f.write(
            test_user_client_certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )


if __name__ == '__main__':
    main()
