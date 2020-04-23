from random import randint


class DiffieHellman:

    DEFAULT_G = 2
    DEFAULT_P = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b225'
                    '14a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f4'
                    '4c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc20'
                    '07cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5'
                    '29077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)

    def __init__(self, g=DEFAULT_G, p=DEFAULT_P):
        self.g = g
        self.p = p
        self._secret_key = randint(1, p - 1)
        self.shared_key = None

    def get_public_key(self):
        return pow(self.g, self._secret_key, self.p)

    def get_shared_secret_key(self, other_party_public_key):
        if self.shared_key is None:
            self.shared_key = pow(other_party_public_key, self._secret_key, self.p)
        return self.shared_key


dh1 = DiffieHellman()
dh2 = DiffieHellman()

# Проверка работоспособности данной реализации
assert dh1.get_shared_secret_key(dh2.get_public_key()) == dh2.get_shared_secret_key(dh1.get_public_key())
