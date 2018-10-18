import json
import hashlib
from urllib import request, error

from Crypto import Random
from Crypto.Cipher import AES

from eth_keyfile import load_keyfile, decode_keyfile_json


def bigint_from_string(v: str) -> float:
    return int(v) / 1e18


class Transport:
    def __init__(self, keyfile: str, password: str, endpoint: str):
        eth_addr, priv_key = self._load_eth_key(keyfile, password)
        self.eth_addr = eth_addr
        self._priv_key = self._pkey_sha256(priv_key)
        self._server = endpoint
        self._block_size = AES.block_size
        self._segment_size = 128

    @staticmethod
    def _load_eth_key(path: str, password: str) -> (str, bytes):
        keyfile_data = load_keyfile(path)
        pkey = decode_keyfile_json(keyfile_data, password)
        return keyfile_data.get('address'), pkey

    @staticmethod
    def _pkey_sha256(key: bytes) -> bytes:
        m = hashlib.sha256()
        m.update(key)
        return m.digest()

    def _encrypt(self, plaintext) -> bytes:
        vec = Random.new().read(AES.block_size)
        aes = AES.new(self._priv_key, AES.MODE_CFB, vec, segment_size=self._segment_size)
        encrypted_text = aes.encrypt(plaintext)
        return vec + encrypted_text

    def _decrypt(self, data: bytes) -> bytes:
        # split message to vector and body
        vec = data[:self._block_size]
        msg = data[self._block_size:]
        aes = AES.new(self._priv_key, AES.MODE_CFB, vec, segment_size=self._segment_size)
        return aes.decrypt(msg)

    def request(self, path, params=None, headers=None, timeout=60) -> dict:
        if not params:
            params = dict()
        if not headers:
            headers = dict()

        plain = json.dumps(params).encode('utf8')
        encrypted = self._encrypt(plain)

        url = self._server + path
        if headers:
            headers.update({'content-type': 'application/json'})

        req = request.Request(url, data=encrypted, headers=headers)

        try:
            resp = request.urlopen(req, timeout=timeout)
            encrypted = resp.read()
            status_code = resp.code
        except error.HTTPError as err:
            encrypted = err.read()
            status_code = err.code

        decrypted = self._decrypt(encrypted)
        unmarshalled = json.loads(decrypted)
        unmarshalled.update({'status_code': status_code})
        return unmarshalled


class Token:
    def __init__(self, transport: Transport):
        self._conn = transport

    def balance(self, whom: str = None) -> dict:
        if not whom:
            whom = self._conn.eth_addr
        resp = self._conn.request('/TokenManagementServer/BalanceOf/', whom)

        resp['liveBalance'] = bigint_from_string(resp.get('liveBalance'))
        resp['liveEthBalance'] = bigint_from_string(resp.get('liveEthBalance'))
        resp['sideBalance'] = bigint_from_string(resp.get('sideBalance'))
        return resp

    def transfer(self, whom: str, amount: int):
        """
        :param whom: ethereum address to send funds
        :param amount: wei-graded value to transfer (use 1e18 is you want to send 1 SNM)
        """
        req = {
            'to':     whom,
            'amount': '%d' % amount,
        }
        resp = self._conn.request('/TokenManagementServer/Transfer/', req)
        return resp


class Order:
    def __init__(self, transport: Transport):
        self._conn = transport

    def status(self, order_id: int) -> dict:
        req = {
            'id': str(order_id),
        }
        resp = self._conn.request('/MarketServer/GetOrderByID/', req)
        return resp


class Deal:
    def __init__(self, transport: Transport):
        self._conn = transport

    def quick_buy(self, order_id: int, force: bool = False) -> dict:
        req = {
            'askID': str(order_id),
            'force': force,
        }
        resp = self._conn.request('/DealManagementServer/QuickBuy/', req)
        return resp

    def status(self, deal_id: int) -> dict:
        resp = self._conn.request('/DealManagementServer/Status/', str(deal_id))
        return resp

    def close(self, deal_id: int, blacklist: bool = False) -> dict:
        req = {
            'id':            str(deal_id),
            'blacklistType': 1 if blacklist else 0,
        }
        resp = self._conn.request('/DealManagementServer/Finish/', req)
        return resp

    def open(self, ask_id: int, bid_id: int, force: bool = False) -> dict:
        req = {
            'askID': str(ask_id),
            'bidID': str(bid_id),
            'force': force,
        }
        resp = self._conn.request('/DealManagementServer/Open/', req)
        return resp

    def list(self, filters: dict) -> dict:
        return self._conn.request('/DWHServer/GetDeals/', filters)


class Worker:
    def __init__(self, transport: Transport):
        self._conn = transport

    def status(self, address) -> dict:
        headers = {'x-worker-eth-addr': address}
        return self._conn.request("/WorkerManagementServer/Status/", headers=headers)


class Task:
    def __init__(self, transport: Transport):
        self._conn = transport

    def status(self, deal_id: int, task_id: str) -> dict:
        req = {
            'id':     task_id,
            'dealID': str(deal_id),
        }
        resp = self._conn.request('/TaskManagementServer/Status/', req)
        return resp


class Node:
    def __init__(self, keyfile: str, password: str, endpoint: str):
        conn = Transport(keyfile, password, endpoint)
        self.token = Token(conn)
        self.order = Order(conn)
        self.deal = Deal(conn)
        self.worker = Worker(conn)
        self.task = Task(conn)


def main():
    key_file = '/Users/alex/go/src/github.com/sonm-io/core/keys/example.key'
    key_password = 'any'
    node_addr = 'http://127.0.0.1:15031'

    node = Node(key_file, key_password, node_addr)
    print(node.token.balance('0x8125721c2413d99a33e351e1f6bb4e56b6b633fd'))


if __name__ == '__main__':
    main()
