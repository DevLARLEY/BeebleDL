import base64
import hashlib
import json
import os
import subprocess
from typing import Tuple
from urllib.parse import urlparse

from Crypto.Cipher import AES
from argon2.low_level import hash_secret, Type


class Beeble:
    def __init__(self, url: str):
        """
        Beeble Downloader
        Author: github.com/DevLARLEY
        """
        self.secret, self.slug = self._parse_url(url)

    @staticmethod
    def _request(url: str, method: str, additional_args: list) -> bytes:
        return subprocess.check_output(['curl', '-X', method, url, *additional_args], shell=False)

    @staticmethod
    def _hash_argon_id(secret: str, salt: str) -> bytes:
        argon_hash = hash_secret(
            secret=secret.encode(),
            salt=salt.encode(),
            time_cost=4,
            memory_cost=10240,
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
        return base64.b64decode(argon_hash.decode().split('$')[-1] + "==")

    def _sync(self, token: str) -> dict:
        request = self._request(
            url="https://serv1c2.beeble.com/v2/share/files/sync",
            method="POST",
            additional_args=[
                "-H", f"Authorization: Bearer {token}",
                '--data-raw', '"{""modseq"":0}"'
            ]
        )
        return json.loads(request)[0]

    @staticmethod
    def _decrypt_gcm(
            ciphertext: bytes,
            key: bytes,
            nonce: bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    ) -> bytes:
        cipher = AES.new(
            key=key,
            mode=AES.MODE_GCM,
            nonce=nonce
        )
        plaintext = cipher.decrypt(ciphertext)
        return plaintext[:-16]

    def get_metadata(self) -> Tuple[str, str, str]:
        salt, token = self._get_metadata(self.slug)
        key = self._hash_argon_id(self.secret, salt)

        synced = self._sync(token)
        pp = base64.b64decode(synced["pp"] + "==")
        password = self._decrypt_gcm(pp, key).decode()

        name_key, _ = self._evp_bytes_to_key(
            password=password.encode(),
            salt=b'\x00\x00\x00\x00\x00\x00\x00\x00',
            key_len=32,
            iv_len=0
        )

        file_name = self._decrypt_gcm(
            ciphertext=base64.b64decode(synced["name"] + "=="),
            key=name_key,
            nonce=base64.b64decode(synced["iv"] + "==")
        ).decode()

        return password, synced["hash"], file_name

    @staticmethod
    def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
        derived_key = b""
        current_digest = b""

        while len(derived_key) < (key_len + iv_len):
            current_digest = hashlib.md5(current_digest + password + salt).digest()
            derived_key += current_digest

        return derived_key[:key_len], derived_key[key_len - iv_len:key_len]

    def download_and_decrypt(self, file_hash: str, password: str, file_name: str):
        self._request(
            url=f"https://s3.pilw.io/files/{file_hash}",
            method="GET",
            additional_args=["-o", "beeble_encrypted"]
        )

        with open("beeble_encrypted", "rb") as f:
            encrypted = f.read()

        key, iv = self._evp_bytes_to_key(
            password=password.encode(),
            salt=encrypted[8:16],
            key_len=48,
            iv_len=16,
        )

        cipher = AES.new(
            key=key[:32],
            mode=AES.MODE_CBC,
            iv=iv
        )

        with open(file_name, "wb") as f:
            f.write(cipher.decrypt(encrypted[16:]))

        os.remove("beeble_encrypted")

    @staticmethod
    def _parse_url(url) -> Tuple[str, str]:
        parsed = urlparse(url)
        return parsed.fragment, parsed.path.split("/")[-1]

    def _get_metadata(self, slug: str) -> Tuple[str, str]:
        request = self._request(
            url=f"https://mail.beeble.com/share/{slug}.json",
            method="GET",
            additional_args=[]
        )
        data = json.loads(request)
        return data["share"]["sl"], data["token"]


if __name__ == '__main__':
    URL = "https://mail.beeble.com/share/........#............"

    beeble = Beeble(URL)
    password, file_hash, file_name = beeble.get_metadata()
    beeble.download_and_decrypt(file_hash, password, file_name)
