from Crypto.Util.number import getPrime
from random import randint
from hashlib import sha256
import os

P = 0
Q = 0
G = 0


def hashGen(message):
    # returns the hash value of the 'message' using sha256

    # print("Hash value of the message is: ", sha256(message.encode()).hexdigest())
    return sha256(message.encode("UTF-8")).hexdigest()


def Inverse_Mod(a, m):  # returns the inverse mod value
    for x in range(1, m):
        if ((a % m) * (x % m)) % m == 1:
            return x
    return -1


def initializationOfParams():
    global P, Q, G
    file_path = "secret.txt"
    if os.path.exists(file_path):
        P, Q, G = open(file_path, "r").read().split()
        P, Q, G = int(P), int(Q), int(G)
    else:
        P = getPrime(20)  # P is prime modulus
        Q = getPrime(10)  # Q is prime divisor
        # Always P should be greater than Q
        # because P-1 must be a multiple of Q
        while (P - 1) % Q != 0:
            P = getPrime(20)
            Q = getPrime(10)

        # print("Prime divisor 'Q': ",Q)
        # print("Prime modulus 'P': ",P)
        h = randint(1, P - 1)  # h is any random number b/w 1 and P-1
        G = 1
        while G == 1:
            G = pow(h, int((P - 1) / Q)) % P  # as G>1 and not =1
        # print("Value of G is : ",G)
        # print(P, Q, G)
        open(file_path, "w").write(str(P) + " " + str(Q) + " " + str(G))
    return (P, Q, G)


def userKeys():
    global P, Q, G
    x = randint(1, Q - 1)
    # print("Randomly chosen Private key is: ",x)
    y = pow(G, x) % P
    # print("Randomly chosen Public key is: ",y)
    return (x, y)


def signature(message, x):
    global P, Q, G
    generated_Hash = hashGen(message)
    r = 0
    s = 0
    while s == 0 or r == 0:
        k = randint(1, Q - 1)
        r = ((pow(G, k)) % P) % Q
        i = Inverse_Mod(k, Q)  # MAssive
        # converting hexadecimal to binary
        hashed = int(generated_Hash, 16)
        s = (i * (hashed + (x * r))) % Q
    return (r, s, k)


def verification(message, r, s, y):
    global P, Q, G
    generated_Hash = hashGen(message)

    # computing w
    w = Inverse_Mod(s, Q)
    # print("w is : ",w)

    hashed = int(generated_Hash, 16)

    # computing u1, u2 and v
    u1 = (hashed * w) % Q
    u2 = (r * w) % Q
    v = ((pow(G, u1) * pow(y, u2)) % P) % Q

    # print("u1 is: ",u1)
    # print("u2 is: ",u2)
    # print("v is : ",v)

    if v == r:
        return True
    else:
        return False


global_var = initializationOfParams()
if __name__ == "__main__":
    keys = userKeys()
    # P,Q,G are the global variables
    # x private key, y is public key

    # Sender's side (signing the document):
    print()
    message = input("Enter the message to sign: ")
    components = signature(message, keys[0])

    print("r(Component of signature) is: ", components[0])
    print("k(Randomly chosen number) is: ", components[2])
    print("s(Component of signature) is: ", components[1])

    # Receiver's side (verifying the sign):
    print()
    message = input("Enter the message to verify: ")
    verification(message, components[0], components[1], keys[1])
