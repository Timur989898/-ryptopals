from base64 import b64decode
from math import ceil, log
from decimal import *
from tes39 import to_bytes, RSA
 
 
class RSAParityOracle(RSA):
 
    def is_parity_odd(self, data):
        p = pow(data, self._d, self.n)
        return p & 1
 
 
class Attack(object):
 
    @staticmethod
    def parity_oracle_attack(text, rsa_parity_oracle, h=False):
        multiplier = pow(
            2,
            rsa_parity_oracle.e,
            rsa_parity_oracle.n
        )
 
        lower_bound = Decimal(0)
        upper_bound = Decimal(rsa_parity_oracle.n)
       
        f = lambda x: int(ceil(log(x, 2)))
        g = lambda x: int_to_bytes(int(x))
 
        getcontext().prec = f(rsa_parity_oracle.n)
 
        for i in range(f(rsa_parity_oracle.n)):
            text = (text * multiplier) % rsa_parity_oracle.n
 
            if rsa_parity_oracle.is_parity_odd(text):
                lower_bound = (lower_bound + upper_bound) / 2
            else:
                upper_bound = (lower_bound + upper_bound) / 2
 
            if h is True:
                print(g(upper_bound))
 
        return g(upper_bound)
 
 
def main():
    input_value = b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IG"
                            "Fyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
 
    rsa_parity_oracle = RSAParityOracle(1024)
 
    ciphertext = rsa_parity_oracle.encrypt(input_value)
    rsa_parity_oracle.decrypt(ciphertext)

    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)
    assert plaintext == input_value
 
 
if __name__ == '__main__':
    main()