from Crypto.Util.number import getPrime


class RSA(object):

    def __init__(self, length):
        self.e = 3
        phi = 0

        while True:
            if gcd(self.e, phi) == 1:
                break

            p = getPrime(length // 2)
            q = getPrime(length // 2)
            phi = lcm(p - 1, q - 1)
            self.n = p * q

        self.d = mod_inv(self.e, phi)

    def encrypt(self, binary_data):
        return pow(
            int.from_bytes(
                binary_data,
                byteorder='big'
            ),
            self.e,
            self.n
        )

    def decrypt(self, encrypted_int_data):
        return to_bytes(
            pow(encrypted_int_data, self.d, self.n)
        )


def gcd(lhs, rhs):
    return gcd(rhs, lhs % rhs) if rhs else lhs


def lcm(lhs, rhs):
    return lhs * rhs // gcd(lhs, rhs)


def to_bytes(n):
    return n.to_bytes(
        (n.bit_length() + 7) // 8,
        'big'
    )


class NotInvertibleException(Exception):
    pass


def mod_inv(a, n):
    t0 = 0
    r0 = n
    t1 = 1
    r1 = a

    while r1 != 0:
        t0 = t1
        t1 = t0 - (r0 // r1) * t1
        r0 = r1
        r1 = r0 - (r0 // r1) * r1

    if r0 <= 1:
        return t1 + n if t0 < 0 else t0

    raise NotInvertibleException('Cannot be inverted')


def main():
    assert mod_inv(17, 3120) == 2753
    mess = b"123456543212345"
    rsa = RSA(1024)
    assert rsa.decrypt(rsa.encrypt(mess)) == mess


if __name__ == '__main__':
    main()