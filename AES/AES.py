from AESTables import *
from AESHelp import InToState, OutFromState, xor


#
# Functions used in the AES Key Expansion routine
#
def RotWord(word):
    '''
  RotWord(word) -> word

  RotWord takes four-byte input word and performs
  a cyclic permutation. It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    return word[1:] + bytes([word[0]])


def SubWord(word):
    '''
  SubWord(word) -> word

  SubWord that takes a four-byte input word and
  applies an S-box to each of the four bytes to
  produce an output word. It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    out = bytearray()
    for i in range(4):
        out.append(sbox[word[i]])
    return out


#
# AES Key expansion routine
#
def KeyExpansion(key, Nk, Nb=4):
    '''
  KeyExpansion(key, Nk, Nb=4) -> key list

  KeyExpansion generates a series of Round Keys (key list)
  from the Cipher Key (key).
  Nk is the number of 32-bit words comprising the Cipher Key (key).
    For this standard, Nk = 4, 6, or 8.
  Nb is the number of columns (32-bit words) comprising the state.
    For this standard, Nb = 4.
  KeyExpansion is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    Nr = Nk + 6
    i = 0
    w = []
    keyL = key.to_bytes(Nk * 4, 'big')
    for i in range(0, Nk * 4, 4):
        w += [keyL[i:i + 4]]
    i = Nk
    for i in range(Nk, (Nb * (Nr + 1))):
        temp = bytearray(w[i - 1])
        if i % Nk == 0:
            temp = SubWord(RotWord(temp))
            temp[0] = temp[0] ^ rcon[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = SubWord(temp)
        w += [xor(w[i - Nk], temp)]
    return w


#
# Subordinate Functions for those
# Functions used by AES Cipher
# and AES Inverse Cipher
#
def GFMult(a, b, n=8, ip=0x11b):
    '''
  GFMult(a, b, n=8, ip=0x11b) -> number

  GFMult performs finite field multiplication for for Galois
  Field 2^n using irreducible polynomial ip. Based on algorithm
  found at http://en.wikipedia.org/wiki/Finite_field_arithmetic.'''
    p = 0
    test = 2 ** n
    while n > 0:
        f = 0
        if b & 1 == 1:
            p = p ^ a
        else:
            p = p ^ 0
        a = a << 1
        if a & test == test:
            a = a ^ ip
        else:
            a = a ^ 0
        b = b >> 1
        n = n - 1
    return p


def GFMul(a, b):
    '''
  GFMul(a, b) -> number

  GFMul is a Galois Field Multiplication function that is
  equivalent to GFMult, but is based on log and exponent
  table lookup to increase security against side channel
  attacks.  Based on algortihm found at
  http://www.samiam.org/galois.html.'''
    z = 0
    s = ltable[a] + ltable[b]
    s %= 255
    s = atable[s]
    q = s
    if a == 0:
        s = z
    else:
        s = q
    if b == 0:
        s = z
    else:
        q = z
    return s


def GetColumns(state, Nb=4):
    '''
  GetColumns(state, Nb=4) -> column list

  GetColumns converts a state (2D array of longs) into
  a column list (2D array of longs).
  GetColumns is its own inverse, i.e.
    state = GetColumns(GetColumns(state)).'''
    out = [[0 for col in range(Nb)] for row in range(4)]
    for col in range(Nb):
        for row in range(4):
            out[col][row] = state[row][col]
    return out


#
# Functions used by AES Cipher
#
def AddRoundKey(state, key, Nb=4):
    '''
  AddRoundKey(state, key, Nb=4) -> state

  Transformation in the Cipher and Inverse Cipher in which a
  Round Key is added to the state using an xor operation. The
  length of a Round Key equals the size of the State (i.e. for
  Nb = 4, the Round Key length equals 128 bits/16 bytes).
  It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    out = []
    s2 = GetColumns(state)
    for i in range(Nb):
        out += [xor(s2[i], key[i])]
    return GetColumns(out)


def SubBytes(state, Nb=4):
    '''
  SubBytes(state, Nb=4) -> state

  SubBytes processes the state (a 2D array of longs) using a
  nonlinear byte substitution table (Sbox) that operates on
  each of the State bytes independently. It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    for col in range(Nb):
        for row in range(4):
            state[row][col] = sbox[state[row][col]]


def ShiftRows(state, Nb=4):
    '''
  ShiftRows(state, NB=4) -> state

  ShiftRows processes the state (a 2D array of longs) by
  cyclically shifting the last three rows of the state
  by different offsets. It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][0:i]


def MixColumns(state, Nb=4):
    '''
  MixColumns(state, Nb=4) -> state

  MixColumns takes all of the columns of the state (2D array
  of longs) and mixes their data independently of one another
  to produce new columns. It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    out = [[0 for row in range(4)] for col in range(Nb)]
    for col in range(Nb):
        out[0][col] = GFMul(0x02, state[0][col]) ^ \
                      GFMul(0x03, state[1][col]) ^ \
                      state[2][col] ^ state[3][col]
        out[1][col] = state[0][col] ^ GFMul(0x02, state[1][col]) \
                      ^ GFMul(0x03, state[2][col]) ^ state[3][col]
        out[2][col] = state[0][col] ^ state[1][col] ^ \
                      GFMul(0x02, state[2][col]) ^ \
                      GFMul(0x03, state[3][col])
        out[3][col] = GFMul(0x03, state[0][col]) ^ state[1][col] \
                      ^ state[2][col] ^ GFMul(0x02, state[3][col])
    return out


#
# AES Cipher
#
def Cipher(IN, keys, Nk, Nb=4):
    '''
  Cipher(IN, key, Nk, Nb = 4) -> state

  Cipher performs a series of tranformations that converts
  plaintext (IN) to ciphertext using the expanded Cipher Key (keys).
  Nk is the number of 32-bit words comprising the Cipher Key.
    For this standard, Nk = 4, 6, or 8.
  Nb is the number of columns (32-bit words) comprising the state.
    For this standard, Nb = 4.
  Cipher is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    state = InToState(IN)
    Nr = Nk + 6
    state = AddRoundKey(state, keys[0:Nb])
    for i in range(1, Nr):
        SubBytes(state)
        ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, keys[i * Nb:(i + 1) * Nb])
    SubBytes(state)
    ShiftRows(state)
    state = AddRoundKey(state, keys[Nr * Nb:(Nr + 1) * Nb])
    return OutFromState(state)


#
# Functions used by Inverse Cipher
#
def InvShiftRows(state):
    '''
  InvShiftRows(state) -> state

  Transformation in the Inverse Cipher that is the inverse
  of ShiftRows().  It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]


def InvSubBytes(state, Nb=4):
    '''
  InvSubBytes(state, Nb=4) -> state

  InvSubBytes processes the state (a 2D array of longs) using a
  nonlinear byte substitution table (SboxInv) that operates on
  each of the State bytes independently. It is the inverse of
  SubBytes. It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    for col in range(Nb):
        for row in range(4):
            state[row][col] = sboxInv[state[row][col]]


def InvMixColumns(state, Nb=4):
    '''
  MixColumns(state, Nb=4) -> state

  MixColumns takes all of the columns of the state (2D array
  of longs) and mixes their data independently of one another
  to produce new columns. The inverse of MixColumns.
  It is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    out = [[0 for row in range(4)] for col in range(Nb)]
    for col in range(Nb):
        out[0][col] = GFMul(0x0e, state[0][col]) ^ \
                      GFMul(0x0b, state[1][col]) ^ \
                      GFMul(0x0d, state[2][col]) ^ \
                      GFMul(0x09, state[3][col])
        out[1][col] = GFMul(0x09, state[0][col]) ^ \
                      GFMul(0x0e, state[1][col]) ^ \
                      GFMul(0x0b, state[2][col]) ^ \
                      GFMul(0x0d, state[3][col])
        out[2][col] = GFMul(0x0d, state[0][col]) ^ \
                      GFMul(0x09, state[1][col]) ^ \
                      GFMul(0x0e, state[2][col]) ^ \
                      GFMul(0x0b, state[3][col])
        out[3][col] = GFMul(0x0b, state[0][col]) ^ \
                      GFMul(0x0d, state[1][col]) ^ \
                      GFMul(0x09, state[2][col]) ^ \
                      GFMul(0x0e, state[3][col])
    return out


#
# Inverse Cipher
#
def InvCipher(IN, keys, Nk, Nb=4):
    '''
  InvCipher(IN, key, Nk, Nb = 4) -> state

  InvCipher performs a series of tranformations that converts
  ciphertext (IN) to plaintext using the Cipher Key (key).
  Nk is the number of 32-bit words comprising the Cipher Key.
  For this standard, Nk = 4, 6, or 8.
  Nb is the number of columns (32-bit words) comprising the state.
  For this standard, Nb = 4. InvCipher is defined in the
  FIPS 197: Advanced Encryption Standard (November 26, 2001).'''
    state = InToState(IN)
    Nr = Nk + 6
    state = AddRoundKey(state, keys[Nr * Nb:(Nr + 1) * Nb])
    for i in range(Nr - 1, 0, -1):
        InvShiftRows(state)
        InvSubBytes(state)
        state = AddRoundKey(state, keys[i * Nb:(i + 1) * Nb])
        state = InvMixColumns(state)
    InvShiftRows(state)
    InvSubBytes(state)
    state = AddRoundKey(state, keys[0:Nb])
    return OutFromState(state)