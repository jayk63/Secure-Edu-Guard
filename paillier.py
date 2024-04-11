import random
import math
from Crypto.Util import number


class Paillier:
    def __init__(self):
        self.key_length = 1024
        self.public_key, self.private_key = self.generate_key_pair()

    def generate_key_pair(self):
        p = number.getPrime(self.key_length // 2)
        q = number.getPrime(self.key_length // 2)
        n = p * q
        nsq = n * n
        g = n + 1
        lambda_val = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        mu = number.inverse(lambda_val, n)
        public_key = (n, g)
        private_key = (lambda_val, mu)
        return public_key, private_key

    def encrypt(self, m):
        r = random.randint(1, self.public_key[0])
        n = self.public_key[0]
        g = self.public_key[1]
        c = pow(g, m, n * n) * pow(r, n, n * n) % (n * n)
        # print("Encrypted ciphertext:", c)
        # print("r:", r)
        # print("n:", n)
        return c

    def decrypt(self, c):
        n = self.public_key[0]
        lambda_val = self.private_key[0]
        mu = self.private_key[1]
        x = pow(c, lambda_val, n * n) - 1
        # print("x:", x)
        plaintext = (x // n * mu) % n
        # print("Decrypted message:", plaintext)
        return plaintext

    def homomorphic_add(self, c1, c2):
        n = self.public_key[0]
        c3 = c1 * c2 % (n * n)
        return c3

    def homomorphic_scalar(self, c, k):
        n = self.public_key[0]
        c1 = pow(c, k, n * n)
        return c1
