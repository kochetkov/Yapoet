from random import getrandbits

from attackenginebase import AttackEngineBase
from attackresult import AttackResult


class CbcAttackEngine(AttackEngineBase):
    def _decrypt_block_cbc(self, encrypted_block, verbose):
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
                    if verbose:
                        print("%02X " % intermediate_bytes[byte_index], end="", flush=True)
                    break
                else:
                    if probing_bytes[byte_index] == 0:
                        if verbose:
                            print("can't decrypt block")
                        return None
                    probing_bytes[byte_index] = probing_bytes[byte_index] + 1 if probing_bytes[byte_index] != 255 else 0
            byte_index -= 1
        return intermediate_bytes

    def decrypt(self, encrypted_data):
        self._requests_count = 0
        encrypted_bytes = self._decode_func(encrypted_data)
        decrypted_bytes = bytearray(b'\0' * len(encrypted_bytes))
        decrypted_index = 0
        block_index = len(encrypted_bytes) - self._block_size
        while block_index >= 0:
            print("\nProcessing block #%02X: " % int(block_index / self._block_size), end="")
            cipher_block = encrypted_bytes[block_index: block_index + self._block_size]
            if block_index > 0:
                prev_block = encrypted_bytes[block_index - self._block_size: block_index]
            else:
                prev_block = self._iv
            decrypted_block = self._decrypt_block_cbc(cipher_block, True)
            if decrypted_block is None:
                return None
            for idx, val in enumerate(decrypted_block):
                decrypted_bytes[decrypted_index] = val ^ prev_block[idx]
                decrypted_index += 1
            block_index -= self._block_size
        return AttackResult(decrypted_bytes, self._requests_count)

    def _encrypt_block_cbc(self, plain_block, iv):
        encrypted_block = bytearray(b'\0' * self._block_size)
        decrypted_block = self._decrypt_block_cbc(iv, False)
        if decrypted_block is not None:
            for idx, val in enumerate(decrypted_block):
                encrypted_block[idx] = val ^ plain_block[idx]
                print("%02X " % encrypted_block[idx], end="", flush=True)
            return encrypted_block
        else:
            print("can't encrypt block")
            return None

    def encrypt(self, plaintext_data):
        self._requests_count = 0
        padding_length = self._block_size - len(plaintext_data) % self._block_size
        padded_data = plaintext_data.encode() + bytearray([padding_length] * padding_length)
        encrypted_text = bytearray()
        block_index = len(padded_data) - self._block_size
        iv = bytearray(getrandbits(8) for _ in range(self._block_size))
        while block_index >= 0:
            print("\nProcessing block #%02X: " % int(block_index / self._block_size), end="")
            encrypted_text = iv + encrypted_text
            iv = self._encrypt_block_cbc(padded_data[block_index: block_index + self._block_size], iv)
            if iv is None:
                return None
            block_index -= self._block_size
        return AttackResult(self._encode_func(iv + encrypted_text), self._requests_count)
