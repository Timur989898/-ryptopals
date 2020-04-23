import hashlib

from Crypto import Random
from Crypto.Cipher import AES
from test33 import DiffieHellman
from binascii import unhexlify

def parameter_injection_attack(alice, bob):
    """Имитация атаки."""

    # Алиса вычисляет А
    A = alice.get_public_key()

    # MITM подменяет А
    A = alice.p

    # Боб вычисляет B
    B = bob.get_public_key()

    # MITM подменяет B
    B = bob.p

    # Алиса отправляет зашифрованное сообщение
    _msg = b'1234567891234567'
    iv = Random.new().read(AES.block_size)
    sha1_key = hashlib.sha1(hex(alice.get_shared_secret_key(B))).hexdigest()[:16]
    aes = AES.new(sha1_key, mode=AES.MODE_CBC, IV=iv)
    a_question = aes.encrypt(_msg) + iv

    # MITM пропускает его через себя

    # Боб расшифровывает сообщение, шифрует и отправляет 
    iv = a_question[-AES.block_size:]
    msg = a_question[:-AES.block_size]
    sha1_key = hashlib.sha1(hex(bob.get_shared_secret_key(A))).hexdigest()[:16]
    aes = AES.new(sha1_key, mode=AES.MODE_CBC, IV=iv)
    b_answer = aes.decrypt(msg)

    # MITM пропускает его через себя

    # MITM расшифровывает перехваченные сообщения
    #
    # Найти ключ после замены A и B на p не составляет труда
    mitm_hacked_key = hashlib.sha1(hex(0L)).hexdigest()[:16]

    # Взлом Алисы
    mitm_a_iv = a_question[-AES.block_size:]
    aes = AES.new(mitm_hacked_key, mode=AES.MODE_CBC, IV=mitm_a_iv)
    mitm_hacked_message_a = aes.decrypt(a_question[:-AES.block_size])

    # Проверка успешности атаки
    assert _msg == mitm_hacked_message_a == b_answer


alice = DiffieHellman()
bob = DiffieHellman()
parameter_injection_attack(alice, bob)
