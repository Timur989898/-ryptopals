from test39 import RSA, mod_inv, to_bytes
 

def rsa_broadcast_attack(ciphertexts):
    c0 = ciphertexts[0][0]
    c1 = ciphertexts[1][0]
    c2 = ciphertexts[2][0]
   
    n0 = ciphertexts[0][1]
    n1 = ciphertexts[1][1]
    n2 = ciphertexts[2][1]
   
    m0 = n1 * n2
    m1 = n0 * n2
    m2 = n0 * n1
 
    t0 = (c0 * m0 * mod_inv(m0, n0))
    t1 = (c1 * m1 * mod_inv(m1, n1))
    t2 = (c2 * m2 * mod_inv(m2, n2))
 
    c = (t0 + t1 + t2) % (n0 * n1 * n2)
 
    return int_to_bytes(
        int(c ** (1 / 3)) if int(c ** (1 / 3)) ** 3 == c else int(c ** (1 / 3)) + 1
    )
 
 
def main():
    ciphertexts = []
    plaintext = b"123456543212345"
    for _ in range(3):
        rsa = RSA(1024)
        ciphertexts.append((rsa.encrypt(plaintext), rsa.n))
 
    assert rsa_broadcast_attack(ciphertexts) == plaintext
 
 
if __name__ == '__main__':
    main()