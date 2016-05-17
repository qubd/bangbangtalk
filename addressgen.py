import mini_ecdsa
import hashlib

C = mini_ecdsa.CurveOverFp.secp256k1()
P = mini_ecdsa.Point.secp256k1()
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

netbyte = '00'
verbyte = '04'

def tobase58(s):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    inp = int(s, 16)
    out = ''

    while inp > 0:
        quo, rem = divmod(inp, 58)
        out += alphabet[rem]
        inp = quo

    #Add a one for each leading zero byte in the address.
    i = 0
    while s[i:i+2] == '00':
        out += alphabet[0];
        i += 2

    return out[::-1]

def checksum(hash160):
    sha_once = hashlib.new('sha256', bytearray.fromhex(hash160)).hexdigest()
    sha_twice = hashlib.new('sha256', bytearray.fromhex(sha_once)).hexdigest()
    return sha_twice[:8]

def new_address():
    private_key, public_key = mini_ecdsa.generate_keypair(C, P, n)

    strx = str("%x" % public_key.x)
    stry = str("%x" % public_key.y)

    while len(strx) < 64:
        strx = '0' + strx
    while len(stry) < 64:
        stry = '0' + stry

    return build_address(strx, stry)

def new_compressed_address():
    private_key, public_key = mini_ecdsa.generate_keypair(C, P, n)

    strx = str("%x" % public_key.x)
    stry = str("%x" % public_key.y)

    while len(strx) < 64:
        strx = '0' + strx
    while len(stry) < 64:
        stry = '0' + stry

    return build_compressed_address(strx, stry)

def from_privkey(d):
    return from_pubkey(C.mult(P,d))

def from_pubkey(public_key):
    strx = str("%x" % public_key.x)
    stry = str("%x" % public_key.y)

    while len(strx) < 64:
        strx = '0' + strx
    while len(stry) < 64:
        stry = '0' + stry

    return build_address(strx, stry)

def from_coords(x,y):
    strx = str("%x" % x)
    stry = str("%x" % y)

    while len(strx) < 64:
        strx = '0' + strx
    while len(stry) < 64:
        stry = '0' + stry

    return build_address(strx, stry)

def compressed_from_privkey(d):
    return compressed_from_pubkey(C.mult(P,d))

def compressed_from_pubkey(public_key):
    strx = str("%x" % public_key.x)
    stry = str("%x" % public_key.y)

    while len(strx) < 64:
        strx = '0' + strx
    while len(stry) < 64:
        stry = '0' + stry

    return build_compressed_address(strx, stry)

def compressed_from_coords(x,y):
    strx = str("%x" % x)
    stry = str("%x" % y)

    while len(strx) < 64:
        strx = '0' + strx
    while len(stry) < 64:
        stry = '0' + stry

    return build_compressed_address(strx, stry)

def build_address(str_x, str_y):
    pub_key_string = verbyte + str_x + str_y

    sha = hashlib.new('sha256', bytearray.fromhex(pub_key_string)).hexdigest()
    rmd = netbyte + hashlib.new('ripemd160', bytearray.fromhex(sha)).hexdigest()

    return from_hash160(rmd)

def from_hash160(hash160):
    return tobase58(hash160 + checksum(hash160))

def build_address_no_vbyte(strx, stry):
    pub_key_string = strx + stry

    sha = hashlib.new('sha256', bytearray.fromhex(pub_key_string)).hexdigest()
    hash160 = netbyte + hashlib.new('ripemd160', bytearray.fromhex(sha)).hexdigest()

    return from_hash160(hash160)

def build_address_zero_vbyte(strx, stry):
    pub_key_string = '00' + strx + stry

    sha = hashlib.new('sha256', bytearray.fromhex(pub_key_string)).hexdigest()
    hash160 = netbyte + hashlib.new('ripemd160', bytearray.fromhex(sha)).hexdigest()

    return from_hash160(hash160)

def build_address_no_ibyte(strx, stry):
    pub_key_string = verbyte + strx + stry

    sha = hashlib.new('sha256', bytearray.fromhex(pub_key_string)).hexdigest()
    hash160 = hashlib.new('ripemd160', bytearray.fromhex(sha)).hexdigest()

    return from_hash160(hash160)

def build_compressed_address2(strx, stry):
    pub_key_string = '02' + strx

    sha = hashlib.new('sha256', bytearray.fromhex(pub_key_string)).hexdigest()
    hash160 = netbyte + hashlib.new('ripemd160', bytearray.fromhex(sha)).hexdigest()

    return from_hash160(hash160)

def build_compressed_address3(strx, stry):
    pub_key_string = '03' + strx

    sha = hashlib.new('sha256', bytearray.fromhex(pub_key_string)).hexdigest()
    hash160 = netbyte + hashlib.new('ripemd160', bytearray.fromhex(sha)).hexdigest()

    return from_hash160(hash160)
