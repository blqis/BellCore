print("1 :\n")

from Crypto.Util.number import *
from random import *
import math
import time

# 1.

p = getPrime(512)
q = getPrime(512)

while(p == q):
    q = getPrime(512)

n = p * q
phi_n = (p - 1) * (q - 1)

e = 65537

while (math.gcd(e, phi_n) != 1 ):
    e = randint(1, (phi_n - 1))

d = inverse(e, phi_n)

dp = d % (p - 1)
dq = d % (q - 1)
iq = pow(q, -1, p)

pk_rsa = (n, e)
sk_rsa = d

pk_crtrsa = (n, e)
sk_crtrsa = p, q, dp, dq, iq

m = randint(0, n)

# 2.

def rsa_sign(m, sk, n):

    s = pow(m, sk, n)

    return s


def crt_rsa_sign(c, sk):

    p, q, dp, dq, iq = sk

    mp = pow(c, dp, p)
    mq = pow(c, dq, q)

    h = (iq * (mp - mq)) % p

    s = mq + h * q

    return s

# print(crt_rsa_sign(m, sk_crtrsa) == rsa_sign(m, sk_rsa, n)) # True


### Mesure de temps pour le calcul de la signature

# RSA

start_time = time.time()

for _ in range(1000):
    rsa_sign(m, sk_rsa, n)

end_time = time.time()

rsa_time = end_time - start_time

# CRT-RSA

start_time = time.time()

for _ in range(1000):
    crt_rsa_sign(m, sk_crtrsa)

end_time = time.time()

crt_rsa_time = end_time - start_time


facteur_vitesse = rsa_time / crt_rsa_time


print(f"1000 signatures RSA effectuées en {rsa_time} secondes.")
print(f"1000 signatures CRT-RSA effectuées en {crt_rsa_time} secondes.")
print(f"La signature CRT-RSA est ~{round(facteur_vitesse, 2)}x plus rapide.\n\n")



"""************ Exercice 2 ************"""

print("2 :\n")

# 1. Injecter le registre 5 avec un nombre aléatoire génère un s fauté.
# 2. De là, il suffit de procéder au calcul suivant : p = gcd(n, s - faute), q = n//p.

N = 47775493107113604137
e = 17
p = math.gcd(N, int('0x3f010be37eb5eca9', 16) - int('0x3cede024192d7695', 16))
q = N // p

phi_N = (p - 1) * (q - 1)

d = pow(e, -1, phi_N)

print(f"p, q = {p, q}.\nClé privée (d) : {d}.")
