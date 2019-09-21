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
    result = "".join(["%x" % (int(x, 16) ^ int(y, 16)) for (x, y) in zip(hex1, hex2)])
    return bytes.fromhex(result).decode()

# TODO: Suggested steps
# XOR all strings against each other
# If after XORing them there is an alphabetic char, there might be an space
# And if in MANY are an alfabetic char, probably there is a space in the ciphertext!
# Store the positions where you think there is an space
# If you xor the ciphertext, with the space symbol, you'll get the key for that position

import string
import collections

# XORs two string
def strxor(a, b):     # xor two strings (trims the longer input)
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b)])


# El target
target_cipher = ciphers[1]

# Key final
final_key = [None]*150
# Para guardar las letras que sabemos
known_key_positions = set()

for current_index, ciphertext in enumerate(ciphers):

	counter = collections.Counter()

	for index, ciphertext2 in enumerate(ciphers):
		if current_index != index: # para no hacer xor consigo mismo
			for indexOfChar, char in enumerate(strxor(bytes.fromhex(ciphertext).decode(), bytes.fromhex(ciphertext2).decode())): # xor los dos mensajes cifrados
				# al hacer xor si es un caracter alphanumerico, quiere decir que hay un espacio en uno de los textos en plano (no sabemos en cual)				
				if char in string.printable and char.isalpha(): counter[indexOfChar] += 1 # Incrementamos el contador en el index
	knownSpaceIndexes = []

	# Loop through all positions where a space character was possible in the current_index cipher
	for ind, val in counter.items():
		# If a space was found at least 7 times at this index out of the 9 possible XORS, then the space character was likely from the current_index cipher!
		if val >= 7: knownSpaceIndexes.append(ind)
	#print knownSpaceIndexes # Shows all the positions where we now know the key!

	# Now Xor the current_index with spaces, and at the knownSpaceIndexes positions we get the key back!
	xor_with_spaces = strxor(bytes.fromhex(ciphertext).decode(),' '*150)
	for index in knownSpaceIndexes:
		# Store the key's value at the correct position
		final_key[index] = xor_with_spaces[index].encode()
		# Record that we known the key at this position
		known_key_positions.add(index)

print(final_key)

import binascii
key_hex = binascii.hexlify(b"youfoundthekey!congratulations!!!").decode()

print(str_xor(key_hex, ciphers[3]))

