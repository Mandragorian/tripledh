"""This file is part of tripledh.

tripledh is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

tripledh is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with tripledh.  If not, see <http://www.gnu.org/licenses/>.

Copyright (C)  Andrikopoulos Konstantinos <gkonstandinos@gmail.com>
"""


import dh
import hashlib

from enum import Enum

class HandshakePos(Enum):
	high = 1
	low = 2


class NoLongTermKey(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)


class InvalidHandshakePos(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)


class TripleDH:

	def __hash(self, *values):
		"""Hashes the concatenation of values

		the each element in values must be of type int
		"""
		s = hashlib.sha256()
		for value in values:
			try:
				value_bytes = value.to_bytes(
						value.bit_length() // 8 + 1, byteorder="big")
			except AttributeError:
				value_bytes = str(value)

			s.update(bytes(value_bytes))
		return s.digest()

	def __make_fingerprint(self, pub_key):
		self.__fingerprint = self.__hash(pub_key)
		return self.__fingerprint

	def __init__(self, keyfile=None, trusties=None):
		self.__long_term_key = None
		self.__ephemeral_key = dh.DiffieHellman()
		self.__trusties      = trusties
		self.__secret	     = None
		self.__g_ab	     = None
		self.__g_aB	     = None
		self.__g_Ab	     = None
		self.__keyfile	     = None
		self.__secret	     = None
		self.__fingerprint   = None
		if keyfile:
			"""self.__long_term_key = dh.DiffieHellman()
			self.__long_term_key.readKeyPair(keyfile)"""
			self.load_key_file(keyfile)

	def handshake(self, pub_long_term, pub_ephemeral, position):
		if not self.__long_term_key:
			raise NoLongTermKey("There is no long term key loaded")

		fingerprint = self.__make_fingerprint(pub_long_term)
		if self.__trusties:
			if not (fingerprint in self.__trusties):
				print('pub_key_fingerprint is:', fingerprint)
				print(self.__trusties)
				return False

		self.__ephemeral_key.genKey(pub_ephemeral)
		self.__g_ab = self.__ephemeral_key.getSecret()

		self.__ephemeral_key.genKey(pub_long_term)
		self.__g_aB = self.__ephemeral_key.getSecret()

		self.__long_term_key.genKey(pub_ephemeral)
		self.__g_Ab = self.__long_term_key.getSecret()

		self.__make_secret(position)

	def load_key_file(self, keyfile):
		self.__long_term_key = dh.DiffieHellman()
		self.__long_term_key.readKeyPair(keyfile)

	def __make_secret(self, position):
		if position == HandshakePos.high:
			self.__secret = self.__hash(self.__g_ab, self.__g_aB, self.__g_Ab)
		elif position == HandshakePos.low:
			self.__secret = self.__hash(self.__g_ab,self.__g_Ab, self.__g_aB)
		else:
			raise InvalidHandshakePos("Invalid 3DH position")

	def make_sdata(self, position):
		g_ab_len = (self.__g_ab.bit_length() // 8) + 1
		g_Ab_len = (self.__g_Ab.bit_length() // 8) + 1
		g_aB_len = (self.__g_aB.bit_length() // 8) + 1

		g_ab_bytes = self.__g_ab.to_bytes(g_ab_len, byteorder="big")
		g_Ab_bytes = self.__g_Ab.to_bytes(g_Ab_len, byteorder="big")
		g_aB_bytes = self.__g_aB.to_bytes(g_aB_len, byteorder="big")

		g_ab_len_bytes = g_ab_len.to_bytes(4, byteorder="big")
		g_Ab_len_bytes = g_Ab_len.to_bytes(4, byteorder="big")
		g_aB_len_bytes = g_aB_len.to_bytes(4, byteorder="big")

		if position == HandshakePos.high:
			self.__sdata = b'/0' + g_ab_len_bytes + g_ab_bytes + g_Ab_len_bytes +\
			g_Ab_bytes +  g_aB_len_bytes + g_aB_bytes
		else:
			self.__sdata = b'/0' + g_ab_len_bytes + g_ab_bytes + g_aB_len_bytes +\
			g_aB_bytes + g_Ab_len_bytes + g_Ab_bytes



	def get_secret(self):
		return self.__secret

	def get_fingerprint(self):
		if self.__fingerprint:
			return self.__fingerprint

		long_term_key = self.__long_term_key
		if not long_term_key:
			raise NoLongTermKey("There is no long term key loaded")
		pub_key = long_term_key.publicKey
		return self.__make_fingerprint(pub_key)

	def get_pub_long_term(self):
		return self.__long_term_key.publicKey

	def get_pub_ephemeral(self):
		return self.__ephemeral_key.publicKey
	def get_sdata(self):
		return self.__sdata
	def add_trusted(self, trustee):
		if self.__trusties:
			self.__trusties.append(trustee)
		else:
			self.__trusties = [trustee]



