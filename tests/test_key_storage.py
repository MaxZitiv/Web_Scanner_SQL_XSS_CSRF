import base64
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet

from utils import encryption, key_storage
from utils.encryption import DatabaseEncryption, looks_like_encrypted
from utils.key_storage import KeyStorageError, load_master_key


def test_key_is_created_private_and_reused(tmp_path: Path) -> None:
    path = tmp_path / "key"
    first = load_master_key(path)
    assert len(base64.urlsafe_b64decode(first)) == 32
    assert load_master_key(path) == first
    assert path.read_bytes() == base64.urlsafe_b64decode(first)
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.iterdir()) == [path]


def test_concurrent_creation_never_rotates_or_exposes_partial_key(tmp_path: Path) -> None:
    path = tmp_path / "key"
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(load_master_key, path) for _ in range(24)]
        keys = [future.result() for future in futures]
    assert len(set(keys)) == 1
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("size", [0, 1, 31, 33, 1000])
def test_corrupt_key_is_not_replaced(tmp_path: Path, size: int) -> None:
    path = tmp_path / "key"
    contents = b"k" * size
    path.write_bytes(contents)
    path.chmod(0o600)
    with pytest.raises(KeyStorageError):
        load_master_key(path)
    assert path.read_bytes() == contents


def test_symlink_and_directory_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    load_master_key(real)
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    with pytest.raises(KeyStorageError):
        load_master_key(alias)
    with pytest.raises(KeyStorageError):
        load_master_key(tmp_path)
    assert alias.is_symlink()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_shared_key_permissions_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "key"
    load_master_key(path)
    path.chmod(0o644)
    with pytest.raises(KeyStorageError, match="0600"):
        load_master_key(path)


def test_storage_failure_has_no_predictable_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "key"
    monkeypatch.setattr(key_storage.os, "link", Mock(side_effect=PermissionError("denied")))
    with pytest.raises(KeyStorageError):
        DatabaseEncryption(key_path=path)
    assert not list(tmp_path.iterdir())


def test_existing_ciphertext_and_standard_fernet_both_decrypt(tmp_path: Path) -> None:
    path = tmp_path / "key"
    key = load_master_key(path)
    token = Fernet(key.encode()).encrypt("данные".encode())
    legacy = base64.urlsafe_b64encode(token).decode()
    cipher = DatabaseEncryption(key_path=path, create_key=False)
    assert cipher.decrypt_data(legacy) == "данные"
    assert cipher.decrypt_data(token.decode()) == "данные"
    assert looks_like_encrypted(legacy)
    assert looks_like_encrypted(token.decode())
    assert cipher.decrypt_data(cipher.encrypt_data({"url": "https://scanner.example"})) == {
        "url": "https://scanner.example"
    }


@pytest.mark.parametrize("text", ["", "N/A", "hello", "dGVzdA==", "gAAAAinvalid", "https://scanner.example", "привет"])
def test_plaintext_is_not_treated_as_ciphertext(text: str) -> None:
    assert not looks_like_encrypted(text)


def test_decryption_does_not_create_a_missing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "key"
    token = Fernet(Fernet.generate_key()).encrypt(b"existing encrypted record").decode()
    monkeypatch.setattr(key_storage, "DEFAULT_KEY_PATH", path)
    monkeypatch.setattr(encryption, "_encryption_instance", None)
    assert encryption.decrypt_sensitive_data_safe(token, "unavailable") == "unavailable"
    assert not path.exists()
    with pytest.raises(KeyStorageError):
        encryption.decrypt_sensitive_data(token)
    assert not path.exists()


def test_explicit_key_location_for_read_only_installation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "private-key"
    key = load_master_key(path)
    monkeypatch.setenv("WEB_SCANNER_KEY_FILE", str(path))
    assert load_master_key(create=False) == key
    monkeypatch.setenv("WEB_SCANNER_KEY_FILE", "relative-key")
    with pytest.raises(KeyStorageError, match="абсолютный"):
        load_master_key()


def test_unavailable_key_prevents_partial_database_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, history_database: object
) -> None:
    from utils.database import Database

    assert isinstance(history_database, Database)
    path = tmp_path / "corrupt-key"
    path.write_bytes(b"bad")
    path.chmod(0o600)
    monkeypatch.setattr(key_storage, "DEFAULT_KEY_PATH", path)
    assert not history_database.save_scan_async(1, "https://scanner.example", [], "sql")
    assert history_database.get_scan_statistics(1)["total_scans"] == 2
    assert path.read_bytes() == b"bad"
