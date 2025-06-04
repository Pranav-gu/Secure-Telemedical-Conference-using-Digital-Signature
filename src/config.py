import random
from sympy import randprime, mod_inverse
from Crypto.Cipher import AES
import base64
import time

HOST = "localhost"
MASTER_PORT = 8080
MASTER_SERVER = "localhost"

MESSAGE_SIZE = 1024
DELTA_TS = 60

NAMES = ['Patient 1', 'Patient 2', 'Patient 3']
PORTS = [8000, 8001, 8002]


def gcd(x, y):
    while(y):
       x, y = y, x % y
    return abs(x)


def binpow(a, b, m):
    a %= m
    res = 1
    while b > 0:
        if b & 1:
            res = (res * a) % m
        a = (a * a) % m
        b >>= 1
    return res


def generate_keys(n=10):
    start_time = time.time()
    p = randprime(2**(n-1), 2**n)
    g = random.randint(2, p-1)
    x = random.randint(2, p-2)
    y = binpow(g, x, p)
    end_time = time.time()
    elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
    print('Time taken for key-generation :',elapsed_time)
    return (p, g, y), x


def encrypt(message, public_key):
    p, g, y = public_key
    m = message

    k = random.randint(2, p-2)
    c1 = binpow(g, k, p)
    c2 = (m * binpow(y, k, p)) % p
    return c1, c2


def decrypt(cipher, public_key, private_key):
    p, _, _ = public_key
    x = private_key
    c1, c2 = cipher
    s = binpow(c1, x, p)
    s_inv = binpow(s, p-2, p)
    m = (c2 * s_inv) % p
    return m


def sign(message, public_key, private_key):

    start_time = time.time()

    p, g, _ = public_key
    x = private_key
    m = int.from_bytes(message.encode(), 'big')

    while True:
        k = random.randint(2, p-2)
        if gcd(k, p-1) == 1:
            break

    r = binpow(g, k, p)
    k_inv = mod_inverse(k, p-1)
    s = (k_inv * (m - x*r)) % (p-1)

    end_time = time.time()
    elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
    print('Time taken for signing :',elapsed_time)

    return r, s


def verify(message, public_key, sign):

    start_time = time.time()

    p, g, y = public_key
    r, s = sign
    m = int.from_bytes(message.encode(), 'big')

    if not (1 <= r <= p-1):
        return False
    
    lhs = (binpow(y, r, p) * binpow(r, s, p)) % p
    rhs = binpow(g, m, p)

    end_time = time.time()
    elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
    print('Time taken for verification :',elapsed_time)

    return lhs == rhs


class AESFunctions():
    def __init__(self, key=b'Sixteen byte key'):
        self.key = self.adjust_key_length(key, 32)
        
    def adjust_key_length(self, key, target_length):
        if len(key) == target_length:
            return key
        elif len(key) > target_length:
            return key[:target_length]
        else:
            return key + b' ' * (target_length - len(key))

    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext + tag + nonce
    
    def encrypt_to_base64(self, data):
        encrypted_binary = self.encrypt(data)
        return base64.b64encode(encrypted_binary).decode('ascii')

    def decrypt(self, encrypted_data):
        nonce = encrypted_data[-16:]
        tag = encrypted_data[-32:-16]
        ciphertext = encrypted_data[:-32]

        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
        except ValueError:
            print("Key incorrect or message corrupted")
        return plaintext
    
    def decrypt_from_base64(self, base64_string):
        encrypted_binary = base64.b64decode(base64_string)
        return self.decrypt(encrypted_binary)