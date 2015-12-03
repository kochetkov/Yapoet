from abc import ABCMeta, abstractmethod
from urllib.parse import quote
from urllib.request import urlopen
from urllib.request import Request
from urllib.error import HTTPError
from urllib.error import URLError
from errno import EHOSTUNREACH


class AttackEngineBase(metaclass=ABCMeta):
    def __init__(self, url, post_data, cookie, block_size, iv, mode, encode_func, decode_func):
        self._url = url
        self._post_data = post_data
        self._cookie = cookie
        self._block_size = block_size
        self._iv = iv
        self._mode = mode
        self._encode_func = encode_func
        self._decode_func = decode_func
        self._requests_count = 0

    def _specify(self, template_string, encrypted_data):
        return template_string.replace("%encrypted_data%", quote(self._encode_func(encrypted_data)))

    def _is_valid_padding(self, encrypted_data):
        url = self._specify(self._url, encrypted_data)
        post_data = self._specify(self._post_data, encrypted_data).encode() if self._post_data else None
        cookie = {"Cookie": self._specify(self._cookie, encrypted_data)} if self._cookie else {}
        try:
            self._requests_count += 1
            urlopen(Request(url, post_data, cookie))
            return True
        except HTTPError:
            return False
        except URLError:
            print("\n\nFATAL ERROR: host is unreachable")
            exit(EHOSTUNREACH)

    @abstractmethod
    def decrypt(self, encrypted_data):
        raise NotImplementedError

    @abstractmethod
    def encrypt(self, plaintext_data):
        raise NotImplementedError
