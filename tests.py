import unittest
from itertools import chain
from pychacha20poly1305 import AeadChaCha20Poly1305, ChaCha20, Poly1305

# All tests taken from rfc8439

class ChaCha20Tests(unittest.TestCase):
	def test_vector_1(self):
		plaintext = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		ciphertext = \
			"76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28"\
			"bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7"\
			"da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37"\
			"6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86"
		key = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
		count = 0

		chacha20 = ChaCha20(bytes.fromhex(key), bytes.fromhex(nonce), count)
		result = bytes(chain.from_iterable(chacha20.encrypt(bytes.fromhex(plaintext))))

		self.assertEqual(result, bytes.fromhex(ciphertext))

	def test_vector_2(self):
		plaintext = \
			"Any submission to the IETF intended by the Contributor for publication "\
			"as all or part of an IETF Internet-Draft or RFC and any statement made "\
			"within the context of an IETF activity is considered an \"IETF Contribution\". "\
			"Such statements include oral statements in IETF sessions, "\
			"as well as written and electronic communications made at any time or place, which are addressed to"
		ciphertext = \
			"a3 fb f0 7d f3 fa 2f de 4f 37 6c a2 3e 82 73 70"\
			"41 60 5d 9f 4f 4f 57 bd 8c ff 2c 1d 4b 79 55 ec"\
			"2a 97 94 8b d3 72 29 15 c8 f3 d3 37 f7 d3 70 05"\
			"0e 9e 96 d6 47 b7 c3 9f 56 e0 31 ca 5e b6 25 0d"\
			"40 42 e0 27 85 ec ec fa 4b 4b b5 e8 ea d0 44 0e"\
			"20 b6 e8 db 09 d8 81 a7 c6 13 2f 42 0e 52 79 50"\
			"42 bd fa 77 73 d8 a9 05 14 47 b3 29 1c e1 41 1c"\
			"68 04 65 55 2a a6 c4 05 b7 76 4d 5e 87 be a8 5a"\
			"d0 0f 84 49 ed 8f 72 d0 d6 62 ab 05 26 91 ca 66"\
			"42 4b c8 6d 2d f8 0e a4 1f 43 ab f9 37 d3 25 9d"\
			"c4 b2 d0 df b4 8a 6c 91 39 dd d7 f7 69 66 e9 28"\
			"e6 35 55 3b a7 6c 5c 87 9d 7b 35 d4 9e b2 e6 2b"\
			"08 71 cd ac 63 89 39 e2 5e 8a 1e 0e f9 d5 28 0f"\
			"a8 ca 32 8b 35 1c 3c 76 59 89 cb cf 3d aa 8b 6c"\
			"cc 3a af 9f 39 79 c9 2b 37 20 fc 88 dc 95 ed 84"\
			"a1 be 05 9c 64 99 b9 fd a2 36 e7 e8 18 b0 4b 0b"\
			"c3 9c 1e 87 6b 19 3b fe 55 69 75 3f 88 12 8c c0"\
			"8a aa 9b 63 d1 a1 6f 80 ef 25 54 d7 18 9c 41 1f"\
			"58 69 ca 52 c5 b8 3f a3 6f f2 16 b9 c1 d3 00 62"\
			"be bc fd 2d c5 bc e0 91 19 34 fd a7 9a 86 f6 e6"\
			"98 ce d7 59 c3 ff 9b 64 77 33 8f 3d a4 f9 cd 85"\
			"14 ea 99 82 cc af b3 41 b2 38 4d d9 02 f3 d1 ab"\
			"7a c6 1d d2 9c 6f 21 ba 5b 86 2f 37 30 e3 7c fd"\
			"c4 fd 80 6c 22 f2 21"
		key = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"
		nonce = "00 00 00 00 00 00 00 00 00 00 00 02"
		count = 1

		chacha20 = ChaCha20(bytes.fromhex(key), bytes.fromhex(nonce), count)
		result = bytes(chain.from_iterable(chacha20.encrypt(plaintext.encode())))

		self.assertEqual(result, bytes.fromhex(ciphertext))

	def test_vector_3(self):
		plaintext = \
			"'Twas brillig, and the slithy toves\n"\
			"Did gyre and gimble in the wabe:\n"\
			"All mimsy were the borogoves,\n"\
			"And the mome raths outgrabe."
		ciphertext = \
			"62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df"\
			"5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf"\
			"16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71"\
			"fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb"\
			"f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6"\
			"1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77"\
			"04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1"\
			"87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1"
		key = \
			"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"\
			"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
		nonce = "00 00 00 00 00 00 00 00 00 00 00 02"
		count = 42

		chacha20 = ChaCha20(bytes.fromhex(key), bytes.fromhex(nonce), count)
		result = bytes(chain.from_iterable(chacha20.encrypt(plaintext.encode())))

		self.assertEqual(result, bytes.fromhex(ciphertext))

class Poly1305Tests(unittest.TestCase):
	def test_vector_1(self):
		key = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		data = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		tag = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(bytes.fromhex(data))

		self.assertEqual(result, bytes.fromhex(tag))

	def test_vector_2(self):
		key = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"
		data = \
			"Any submission to the IETF intended by the Contributor for publication "\
			"as all or part of an IETF Internet-Draft or RFC and any statement made "\
			"within the context of an IETF activity is considered an \"IETF Contribution\". "\
			"Such statements include oral statements in IETF sessions, "\
			"as well as written and electronic communications made at any time or place, which are addressed to"
		tag = "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(data.encode())

		self.assertEqual(result, bytes.fromhex(tag))

	def test_vector_3(self):
		key = \
			"36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		data = \
			"Any submission to the IETF intended by the Contributor for publication "\
			"as all or part of an IETF Internet-Draft or RFC and any statement made "\
			"within the context of an IETF activity is considered an \"IETF Contribution\". "\
			"Such statements include oral statements in IETF sessions, "\
			"as well as written and electronic communications made at any time or place, which are addressed to"
		tag = "f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(data.encode())

		self.assertEqual(result, bytes.fromhex(tag))

	def test_vector_4(self):
		key = \
			"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"\
			"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
		data = \
			"'Twas brillig, and the slithy toves\n"\
			"Did gyre and gimble in the wabe:\n"\
			"All mimsy were the borogoves,\n"\
			"And the mome raths outgrabe."
		tag = "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(data.encode())

		self.assertEqual(result, bytes.fromhex(tag))

	def test_vector_5(self):
		key = \
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		data = "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
		tag = "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(bytes.fromhex(data))

		self.assertEqual(result, bytes.fromhex(tag))


	def test_vector_6(self):
		key = \
			"02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
		data = "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		tag = "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(bytes.fromhex(data))

		self.assertEqual(result, bytes.fromhex(tag))

	def test_vector_7(self):
		key = \
			"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		data = \
			"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"\
			"F0 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"\
			"11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		tag = "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(bytes.fromhex(data))

		self.assertEqual(result, bytes.fromhex(tag))

	def test_vector_8(self):
		key = \
			"01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		data = \
			"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"\
			"FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE"\
			"01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01"
		tag = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"

		poly1305 = Poly1305(bytes.fromhex(key))
		result = poly1305.create_tag(bytes.fromhex(data))

		self.assertEqual(result, bytes.fromhex(tag))

class Poly1305KeyGenerationTests(unittest.TestCase):
	def test_vector_1(self):
		key = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
		nonce = "00 00 00 00 00 00 00 00 00 00 00 00"
		poly_key = \
			"76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28"\
			"bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7"

		result = AeadChaCha20Poly1305.generate_poly1305_key(bytes.fromhex(key), bytes.fromhex(nonce))

		self.assertEqual(result, bytes.fromhex(poly_key))

	def test_vector_2(self):
		key = \
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"\
			"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"
		nonce = "00 00 00 00 00 00 00 00 00 00 00 02"
		poly_key = \
			"ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76"\
			"06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39"

		result = AeadChaCha20Poly1305.generate_poly1305_key(bytes.fromhex(key), bytes.fromhex(nonce))

		self.assertEqual(result, bytes.fromhex(poly_key))

	def test_vector_3(self):
		key = \
			"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"\
			"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
		nonce = "00 00 00 00 00 00 00 00 00 00 00 02"
		poly_key = \
			"96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b"\
			"13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae"

		result = AeadChaCha20Poly1305.generate_poly1305_key(bytes.fromhex(key), bytes.fromhex(nonce))

		self.assertEqual(result, bytes.fromhex(poly_key))

class AeadChaCha20Poly1305Tests(unittest.TestCase):
	def test_vector_1(self):
		ciphertext = \
			"64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd"\
			"5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2"\
			"4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0"\
			"bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf"\
			"33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81"\
			"14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55"\
			"97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38"\
			"36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4"\
			"b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9"\
			"90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e"\
			"af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a"\
			"0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a"\
			"0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e"\
			"ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10"\
			"49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30"\
			"30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29"\
			"a6 ad 5c b4 02 2b 02 70 9b"
		plaintext = \
			"49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20"\
			"61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65"\
			"6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20"\
			"6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d"\
			"6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65"\
			"20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63"\
			"65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64"\
			"20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65"\
			"6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e"\
			"20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72"\
			"69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65"\
			"72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72"\
			"65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61"\
			"6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65"\
			"6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20"\
			"2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67"\
			"72 65 73 73 2e 2f e2 80 9d                     "
		key = \
			"1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"\
			"47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0"
		nonce = "00 00 00 00 01 02 03 04 05 06 07 08"
		additional_data = "f3 33 88 86 00 00 00 00 00 00 4e 91"
		tag = "ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38"

		aead = AeadChaCha20Poly1305(bytes.fromhex(key), bytes.fromhex(nonce), bytes.fromhex(additional_data))
		result_plaintext = bytes(aead.decrypt(bytes.fromhex(ciphertext)))
		result_tag = aead.finish()

		self.assertEqual(result_plaintext, bytes.fromhex(plaintext))
		self.assertEqual(result_tag, bytes.fromhex(tag))

	def test_vector_2(self):
		plaintext = \
			"4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c"\
			"65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73"\
			"73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63"\
			"6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f"\
			"6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20"\
			"74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73"\
			"63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69"\
			"74 2e"
		ciphertext = \
			"d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"\
			"a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"\
			"3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"\
			"1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"\
			"92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"\
			"fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"\
			"3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"\
			"61 16"
		key = \
			"80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"\
			"90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
		nonce = " 07 00 00 00 40 41 42 43 44 45 46 47"
		additional_data = "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7"
		tag = "1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91"

		aead = AeadChaCha20Poly1305(bytes.fromhex(key), bytes.fromhex(nonce), bytes.fromhex(additional_data))
		result_ciphertext = bytes(aead.encrypt(bytes.fromhex(plaintext)))
		result_tag = aead.finish()

		self.assertEqual(result_ciphertext, bytes.fromhex(ciphertext))
		self.assertEqual(result_tag, bytes.fromhex(tag))

if __name__ == "__main__":
	unittest.main()
