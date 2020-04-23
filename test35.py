import hashlib

from Crypto import Random
from Crypto.Cipher import AES
from test33 import DiffieHellman
from binascii import unhexlify

def malicious_g_attack():
    p = DiffieHellman.DEFAULT_P

    for g in [1, p, p - 1]:

        # MITM изменяет g по умолчанию
        alice = DiffieHellman()
        bob = DiffieHellman(g=g)

        # Боб получает g и отправляет подтверждение Алисе

        # Алиса вычисляет А и думает, что отправляет его Бобу
        A = alice.get_public_key()

        # Боб вычисляет B и думает, что отправляет его Алисе
        B = bob.get_public_key()

        # Алиса думает, что отправляет зашифрованное сообщение Бобу
        _msg = b'1234567891234567'
        iv = Random.new().read(AES.block_size)
        sha1_key = hashlib.sha1(hex(alice.get_shared_secret_key(B))).hexdigest()[:16]
        aes = AES.new(sha1_key, mode=AES.MODE_CBC, IV=iv)
        a_question = aes.encrypt(_msg) + iv

        # Боб получает сообщение, но не может расшифровать его 

        # MITM расшифровывает сообщение Алисы
        mitm_a_iv = a_question[-AES.block_size:]

        # Когда g = 1, секретный ключ тоже = 1
        if g == 1:
            sha1_key = hashlib.sha1(b'1').hexdigest()[:16]
            aes = AES.new(sha1_key, mode=AES.MODE_CBC, IV=mitm_a_iv)
            mitm_hacked_message = aes.decrypt(a_question[:-AES.block_size])

        # Когда g равно p, атака работает как атака из задания 34
        elif g == p:
            sha1_key = hashlib.sha1(b'0').hexdigest()[:16]
            aes = AES.new(sha1_key, mode=AES.MODE_CBC, IV=mitm_a_iv)
            mitm_hacked_message = aes.decrypt(a_question[:-AES.block_size])
        else:
            sha1_key = hashlib.sha1(B).hexdigest()[:16]
            aes = AES.new(sha1_key, mode=AES.MODE_CBC, IV=mitm_a_iv)
            mitm_hacked_message = aes.decrypt(a_question[:-AES.block_size])

        # Проверка работоспособности атаки
        assert _msg == mitm_hacked_message


malicious_g_attack()
