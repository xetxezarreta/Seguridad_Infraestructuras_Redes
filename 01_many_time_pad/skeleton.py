# Many time pad lab
# >>> 'a'.encode().hex()
# '61'
# >>> 'A'.encode().hex()
# '41'
# >>> str_xor('61','20')
# 'A'

ciphers = (
    '0d071c154f1c1d4415481519041a550a0c0f0b520d15174c071b1b4f0d1f405252',
    '79221c0d0a194e0d07480b0411594043190b150b41131a0305541d0a0f10494453',
    '104f190f04104e021d1a001c0a0b4a104f0709522a1b1b181915490e4e1f4e5501',
    '1e001a024f01060d1a0f451c005901161c0b470204061309020005164e00404744',
    '790a1b051d0c1e101d070b4b031653431b060e014107011e081a0e1c4e07494852',
    '163b254606064e071504090e01596e2d2a4e131b0c11551c001049090101014001',
    '791d10071c1a00441506014b111140174f0302130f075518091d1a4f1a16595501',
    '790c14084f170b44161a0a000017010a094e131a045405090e04050a4e03545501',
    '384f170f1b550102540d030d0a0b55431b0147000415114c151c0c4f18165358',
    '37001b150a1b1d0d1709094b160d530a01091452151c1418413d49181c1a554401',
    '792655020055000b00480e050a0e0114070f1352151b551b131d1d0a4e1d4e5601')


# finds the xor of 2 hex's and returns ascii
def str_xor(hex1, hex2):
    result = "".join(["%x" % (int(x,16) ^ int(y,16)) for (x, y) in zip(hex1, hex2)])
    return bytes.fromhex(result).decode()

# TODO: Suggested steps
# XOR all strings against each other
# If after XORing them there is an alphabetic char, there might be an space
# And if in MANY are an alfabetic char, probably there is a space in the ciphertext!
# Store the positions where you think there is an space
# If you xor the ciphertext, with the space symbol, you'll get the key for that position

import string
import collections

key_size = 50
final_key = [None]*key_size
known_key_positions = set()

for ciphertext1 in ciphers:
    counter = collections.Counter()
    for ciphertext2 in ciphers:
        if ciphertext1 != ciphertext2: # para no hacer xor entre 2 iguales
            xor = str_xor(ciphertext1, ciphertext2)
            for indexOfChar, char in enumerate(xor):
                if char.isalpha():
                    counter[indexOfChar] += 1

    knownSpaceIndexes = []

    for ind, val in counter.items():
        if val >= 7: 
            knownSpaceIndexes.append(ind)   
   
    # Espacio en hexadecimal es '20'
    xor_with_spaces = str_xor(ciphertext1, '20'*key_size)

    for index in knownSpaceIndexes:
	    final_key[index] = xor_with_spaces[index]
	    known_key_positions.add(index)

print(final_key)

import binascii
# Codificamos la key a hexadecimal.
key_hex = binascii.hexlify(b"youfoundthekey!congratulations!!!").decode()
# Desencriptamos haciendo xor(mensaje, key) y printamos los mensajes 
for index, cipher in enumerate(ciphers):
    print(index + 1, "- ", str_xor(cipher, key_hex))
