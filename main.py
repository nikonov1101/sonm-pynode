import json
import hashlib
from urllib import request

from Crypto import Random
from Crypto.Cipher import AES

from eth_keyfile import load_keyfile, decode_keyfile_json


def bigint_from_string(v: str) -> float:
    return int(v) / 1e18


class Node:
    def __init__(self, keyfile: str, password: str, endpoint: str):
        pkey = self._load_eth_key(keyfile, password)
        self._key = self._pkey_sha256(pkey)
        self._server = endpoint
        self._block_size = AES.block_size
        self._segment_size = 128

    @staticmethod
    def _load_eth_key(path: str, password: str) -> bytes:
        keyfile_data = load_keyfile(path)
        pkey = decode_keyfile_json(keyfile_data, password)
        return pkey

    @staticmethod
    def _pkey_sha256(key: bytes) -> bytes:
        m = hashlib.sha256()
        m.update(key)
        return m.digest()

    @property
    def balance(self):
        resp = self._request('/TokenManagementServer/Balance/')
        return {
            'liveBalance':    bigint_from_string(resp.get('liveBalance')),
            'liveEthBalance': bigint_from_string(resp.get('liveEthBalance')),
            'sideBalance':    bigint_from_string(resp.get('sideBalance')),
        }

    def _encrypt(self, plaintext) -> bytes:
        vec = Random.new().read(AES.block_size)
        aes = AES.new(self._key, AES.MODE_CFB, vec, segment_size=self._segment_size)
        encrypted_text = aes.encrypt(plaintext)
        return vec + encrypted_text

    def _decrypt(self, data: bytes) -> bytes:
        # split message to vector and body
        vec = data[:self._block_size]
        msg = data[self._block_size:]
        aes = AES.new(self._key, AES.MODE_CFB, vec, segment_size=self._segment_size)
        return aes.decrypt(msg)

    def _request(self, path, params=None, timeout=60) -> dict:
        if not params:
            params = dict()

        plain = json.dumps(params).encode('utf8')
        url = self._server + path

        encrypted_req = self._encrypt(plain)
        req = request.Request(url, data=encrypted_req, headers={'content-type': 'application/json'})

        with request.urlopen(req, timeout=timeout) as resp:
            encrypted_resp = resp.read()
            decrypted_resp = self._decrypt(encrypted_resp)
            return json.loads(decrypted_resp)


def main():
    key_file = '/Users/alex/go/src/github.com/sonm-io/core/keys/example.key'
    key_password = 'any'
    node_addr = 'http://127.0.0.1:15031'

    node = Node(key_file, key_password, node_addr)
    print(node.balance)


if __name__ == '__main__':
    main()
