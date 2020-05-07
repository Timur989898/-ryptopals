from test39 import RSA, mod_inv, to_bytes
from random import randint
 
 
class AlreadyDecryptedException(Exception):
    pass
 
 
class RSAServer(object):
 
    def __init__(self, rsa):
        self.rsa = rsa
        self.decrypted = set()
 
    def get_public_key(self):
        return self.rsa.e, self.rsa.n
 
    def decrypt(self, data):
        if data not in self.decrypted:
            self.decrypted.add(data)
            return self.rsa.decrypt(data)
 
        raise AlreadyDecryptedException('Already decrypted!')
 
 
def unpadded_message_recovery(text, server):
    e, n = server.get_public_key()
 
    while True:
        s = randint(2, n - 1)
        if s % n <= 1:
            continue
 
        break
 
    r = (int.from_bytes(server.decrypt((pow(s, e, n) * text) % n), byteorder='big') * mod_inv(s, n)) % n
 
    return int_to_bytes(r)
 
 
def main():
    rsa = RSA(1024)
    plaintext = b"1234565432123452"
    ciphertext = rsa.encrypt(plaintext)
    rsa_server = RSAServer(rsa)
 
    recovered_plaintext = unpadded_message_recovery(ciphertext, rsa_server)
    assert recovered_plaintext == plaintext
 
 
if __name__ == '__main__':
    main()