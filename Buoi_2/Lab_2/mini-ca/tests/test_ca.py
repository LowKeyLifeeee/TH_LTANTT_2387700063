import os
import sys

# Them thu muc mini-ca vao sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from ca_utils import (
    generate_key,
    save_key,
    load_key,
    save_cert,
    load_cert,
    create_root_ca,
    create_intermediate_ca,
    issue_certificate,
    verify_certificate_chain,
    CERTS_DIR
)
from revoke_utils import (
    create_empty_crl,
    revoke_certificate,
    check_revocation_status,
    check_ocsp_status,
    CRL_FILE
)


def test_key_generation_and_storage(tmp_path):
    key = generate_key()
    assert isinstance(key, rsa.RSAPrivateKey)
    assert key.key_size == 2048


def test_root_ca_properties():
    root_key, root_cert = create_root_ca()
    assert root_cert.subject == root_cert.issuer
    bc = root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 1
    # Kiem tra file ton tai
    assert os.path.exists(os.path.join(CERTS_DIR, "root_ca_key.pem"))
    assert os.path.exists(os.path.join(CERTS_DIR, "root_ca_cert.pem"))


def test_intermediate_ca_properties():
    root_key, root_cert = create_root_ca()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    assert inter_cert.issuer == root_cert.subject
    assert inter_cert.subject != root_cert.subject
    bc = inter_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0


def test_issue_end_entity_certificate():
    root_key, root_cert = create_root_ca()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    subject_info = {
        "common_name": "client.test.local",
        "org": "Test Organization",
        "country": "VN"
    }
    user_key, user_cert = issue_certificate(inter_key, inter_cert, subject_info)
    assert user_cert.issuer == inter_cert.subject
    bc = user_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False


def test_verify_certificate_chain():
    root_key, root_cert = create_root_ca()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    subject_info = {"common_name": "app.test.local", "org": "App Org", "country": "VN"}
    app_key, app_cert = issue_certificate(inter_key, inter_cert, subject_info)

    # Chuoi hop le
    valid = verify_certificate_chain(app_cert, [inter_cert, root_cert])
    assert valid is True

    # Chuoi hop le cho intermediate cert
    valid_inter = verify_certificate_chain(inter_cert, [root_cert])
    assert valid_inter is True

    # Chuoi khong hop le (bo qua intermediate cert)
    invalid = verify_certificate_chain(app_cert, [root_cert])
    assert invalid is False


def test_revocation_crl_and_ocsp():
    root_key, root_cert = create_root_ca()
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    subject_info = {"common_name": "revokeme.test.local", "org": "Revoke Org", "country": "VN"}
    rev_key, rev_cert = issue_certificate(inter_key, inter_cert, subject_info)

    cert_path = os.path.join(CERTS_DIR, "revokeme.test.local_cert.pem")
    inter_cert_path = os.path.join(CERTS_DIR, "intermediate_cert.pem")
    inter_key_path = os.path.join(CERTS_DIR, "intermediate_key.pem")

    # Khoi tao CRL
    create_empty_crl(inter_cert, inter_key)

    # Kiem tra truoc khi thu hoi
    assert check_revocation_status(cert_path) is False
    assert check_ocsp_status(rev_cert.serial_number) == "GOOD"

    # Thuc hien thu hoi
    revoke_certificate(cert_path, inter_cert_path, inter_key_path)

    # Kiem tra sau khi thu hoi
    assert check_revocation_status(cert_path) is True
    assert check_ocsp_status(rev_cert.serial_number) == "REVOKED"
