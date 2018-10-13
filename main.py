import json
from urllib import request

from Crypto import Random

from Crypto.Cipher import AES


class Node:
    def __init__(self, key: bytes, endpoint: str):
        self._key = key
        self._server = endpoint
        self._block_size = AES.block_size
        self._segment_size = 128

    @property
    def balance(self):
        return self._request('/TokenManagementServer/Balance/')

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

    def _request(self, path, params=None) -> dict:
        if not params:
            params = dict()

        plain = json.dumps(params).encode('utf8')
        url = self._server + path

        encrypted_req = self._encrypt(plain)
        req = request.Request(url, data=encrypted_req, headers={'content-type': 'application/json'})

        with request.urlopen(req) as resp:
            encrypted_resp = resp.read()
            decrypted_resp = self._decrypt(encrypted_resp)
            return json.loads(decrypted_resp)


with open('/tmp/key', 'rb') as keyfile:
    key = keyfile.read()

    node = Node(key, 'http://127.0.0.1:15031')
    print(node.balance)
