import os
import pytest
from securecrypto import hash_utils
from argon2.exceptions import VerifyMismatchError


def test_hash_password_and_verify():
    # Thong tin nhay cam da duoc loai bo / su dung bien moi truong
    test_pwd = os.environ.get("TEST_PASSWORD", "StrongPass123!")
    hashed = hash_utils.hash_password_secure(test_pwd)
    assert hashed is not None

    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, test_pwd)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == True


def test_wrong_password_verification():
    # Thong tin nhay cam da duoc loai bo / su dung bien moi truong
    test_pwd = os.environ.get("TEST_PASSWORD", "CorrectPass")
    wrong_pwd = os.environ.get("TEST_WRONG_PASSWORD", "WrongPass")
    hashed = hash_utils.hash_password_secure(test_pwd)

    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, wrong_pwd)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == False
