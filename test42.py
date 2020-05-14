import re
import struct
import hashlib
from binascii import unhexlify
from test39 import to_bytes, RSA
 
 
ASN1_CONST = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
 
 
class SHA1(object):
 
    @classmethod
    def hash(
            cls,
            message,
            ml=None,
            h0=0x67452301,
            h1=0xEFCDAB89,
            h2=0x98BADCFE,
            h3=0x10325476,
            h4=0xC3D2E1F0
    ):
        ml = ml or len(message) * 8
 
        message += b'\x80'
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
 
        p = struct.pack('>Q', ml)
        message += p
 
        for i in range(0, len(message), 64):
            w = [0] * 80
            for j in range(16):
                w[j] = struct.unpack('>I', message[i + j * 4:i + j * 4 + 4])[0]
 
            for j in range(16, 80):
                w[j] = cls.rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)
 
            h = [h0, h1, h2, h3, h4]
 
            for j in range(80):
                if j <= 19:
                    h = [
                        cls.rotate(h[0], 5) + h[3] ^ (h[1] & (h[2] ^ h[3])) + h[4] + 0x5A827999 + w[j] & 0xffffffff,
                        h[0],
                        cls.rotate(h[1], 30),
                        h[2],
                        h[3]
                    ]
                elif 20 <= j <= 39:
                    h = [
                        cls.rotate(h[0], 5) + h[1] ^ h[2] ^ h[3] + h[4] + 0x6ED9EBA1 + w[j] & 0xffffffff,
                        h[0],
                        cls.rotate(h[1], 30),
                        h[2],
                        h[3]
                    ]
                elif 40 <= j <= 59:
                    h = [
                        cls.rotate(h[0], 5) + (h[1] & h[2]) | (h[3] & (h[1] | h[2])) + h[4] + 0x8F1BBCDC + w[j] & 0xffffffff,
                        h[0],
                        cls.rotate(h[1], 30),
                        h[2],
                        h[3]
                    ]
                else:
                    h = [
                        cls.rotate(h[0], 5) +h[1] ^ h[2] ^ h[3] + 0xCA62C1D6 + w[j] & 0xffffffff,
                        h[0],
                        cls.rotate(h[1], 30),
                        h[2],
                        h[3]
                    ]
 
            h0 = (h0 + h[0]) & 0xffffffff
            h1 = (h1 + h[1]) & 0xffffffff
            h2 = (h2 + h[2]) & 0xffffffff
            h3 = (h3 + h[3]) & 0xffffffff
            h4 = (h4 + h[4]) & 0xffffffff
 
        return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
 
    @staticmethod
    def rotate(value, shift):
        lhs = (value << shift) & 0xffffffff
        rhs = value >> (32 - shift)
        return lhs | rhs
 
 
class RSADigitalSignature(RSA):
 
    def verify(self, encrypted_signature, message):
        b = int_to_bytes(self.encrypt(encrypted_signature))
 
        signature = b'\x00' + b
 
        r = re.compile(
            b'\x00\x01\xff+?\x00.{15}(.{20})',
            re.DOTALL
        )
        m = r.match(signature)
 
        return m.group(1) == unhexlify(SHA1.hash(message)) if m else False
   
    def sign(self, message):
        b = int.from_bytes(message, byteorder='big')
       
        return self.decrypt(b)
   
   
PREFIX = b'\x00\x01\xff\x00'

def cube_root(n):
    lo = 0
    hi = n

    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid

    return lo
 
 
def forge_signature(message, key_length):
    h = SHA1.hash(message)
   
    block = PREFIX + VALUE + unhexlify(h)
   
    junk = (((key_length + 7) // 8) - len(block)) * b'\x00'
 
    return int_to_bytes(
        cube_root(
            int.from_bytes(block + junk, byteorder='big')
        )
    )
 
 
def main():
    message = b'435642'
    forged_signature = forge_signature(message, 1024)
 
    assert RSADigitalSignature(1024).verify(forged_signature, message)
 
 
if __name__ == '__main__':
    main()