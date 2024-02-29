import random
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

E = EllipticCurve(GF(p), [0, 7])

G = E.point( (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8))   # Base point


# Insert Your Signatures Here
r=0x
s=0x
z=0x
def egcd(a, b):

    if a == 0:

        return (b, 0, 1)

    else:

        g, y, x = egcd(b % a, a)

        return (g, x - (b // a) * y, y)
def modinv(a, m):

    g, x, y = egcd(a, m)

    if g != 1:

        raise Exception('modular inverse does not exist')

    else:

        return x % m
def make_public(r,s,z):
    R = E.lift_x(Integer(r))
    w = int(modinv(s, n))
    u1 = int((z * w) % n)
    u2 = int((r * w) % n)
    #R=u1*G + u2*public_key
    #pub= R*modinv(u2,n) - u1*modinv(u2,n)%n
    u_n2=modinv(u2,n)%n
    u_n1=- u1*modinv(u2,n)%n
    
    pub=u_n1*G + u_n2*R
    pub2=u_n1*G + u_n2*(-R)
    return pub,pub2

def verify(r, s,z,public_key):
    w = int(modinv(s, n))
    u1 = int((z * w) % n)
    u2 = int((r * w) % n)
    D=u1*G + u2*public_key
    x,y=D.xy()
    x=int(x)

    if (r % n) == (x % n):
        print( "signature matches")
         
    else:
        print("invalid signature")
           
def calc_u(r,s,z):
    mod_s= modinv(s,n)%n
    u1=int(mod_s*z%n)
    u2=int(mod_s*r%n)
    print("u1:",hex(u1) , "n-u1:",hex(n-u1))
    print("u2:",hex(u2) , "n-u2:",hex(n-u2))
    return u1,u2
u1 , u2 = calc_u(r,s,z)

pub1,pub2=make_public(r,s,z)
print("public_key1",pub1)
print("pub1_x=",hex(pub1.xy()[0]))
print("public_key2",pub2)
print("pub2_x=",hex(pub2.xy()[0]))
verify(r,s,z,pub1)
verify(r,s,z,pub2)
print()

i = 1
found_match = False

while not found_match:
    k = (r * i + z) * modinv(s, n) % n
    print("Invalid K Nonce:", hex(k))
    if k == u1:
        print("Match found for u1 at i =", i)
        found_match = True
    elif k == u2:
        print("Match found for u2 at i =", i)
        found_match = True
    elif k == (n - u1):
        print("Match found for n - u1 at i =", i)
        found_match = True
    elif k == (n - u2):
        print("Match found for n - u2 at i =", i)
        found_match = True
    
    # Compute the new signature point
    P = k * G

    # Check if the x-coordinate of the signature point matches r
    if P.xy()[0] == r:
        print(f"Found k candidate: {k:x}")
        private_key = (s * k - z) * modinv(r, n) % n
        print("Private Key      : %02x" % private_key)
        found_match = True
    
    i += 1

