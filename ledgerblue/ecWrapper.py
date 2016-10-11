"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""

import hashlib
try:
	import secp256k1
	USE_SECP = secp256k1.HAS_ECDH
except ImportError:
	USE_SECP = False

if not USE_SECP:
	import ecpy
	from builtins import int
	from ecpy.curves import Curve, Point
	from ecpy.keys import ECPublicKey, ECPrivateKey
	from ecpy.ecdsa import ECDSA
	CURVE_SECP256K1 = Curve.get_curve('secp256k1')
	SIGNER = ECDSA()

class PublicKey(object):
	def __init__(self, pubkey=None, raw=False, flags=None, ctx=None):
		if USE_SECP:
			if flags == None:
				flags = secp256k1.FLAG_VERIFY
			self.obj = secp256k1.PublicKey(pubkey, raw, flags, ctx)
		else:
			if not raw:
				raise Exception("Non raw init unsupported")
			pubkey = pubkey[1:]
			x = int.from_bytes(pubkey[0:32], 'big')
			y = int.from_bytes(pubkey[32:], 'big')
			self.obj = ECPublicKey(Point(x, y, CURVE_SECP256K1))
					
	def ecdsa_deserialize(self, ser_sig):
		if USE_SECP:
			return self.obj.ecdsa_deserialize(ser_sig)
		else:
			return ser_sig

	def serialize(self, compressed=True):
		if USE_SECP:
			return self.obj.serialize(compressed)
		else:
			if not compressed:
				out = b"\x04"
				out += self.obj.W.x.to_bytes(32, 'big')
				out += self.obj.W.y.to_bytes(32, 'big')
			else:
				out = b"\x03" if ((self.obj.W.y & 1) != 0) else "\x02"
				out += self.obj.W.x.to_bytes(32, 'big')
			return out

	def ecdh(self, scalar):
		if USE_SECP:
			return self.obj.ecdh(scalar)
		else:
			scalar = int.from_bytes(scalar, 'big')
			point = self.obj.W * scalar
			# libsecp256k1 style secret
			out = b"\x03" if ((point.y & 1) != 0) else b"\x02"
			out += point.x.to_bytes(32, 'big')
			hash = hashlib.sha256()
			hash.update(out)
			return hash.digest()

	def ecdsa_verify(self, msg, raw_sig, raw=False, digest=hashlib.sha256):
		if USE_SECP:
			return self.obj.ecdsa_verify(msg, raw_sig, raw, digest)
		else:
			if not raw:
				h = digest()
				h.update(msg)
				msg = h.digest()
			raw_sig = bytearray(raw_sig)
			return SIGNER.verify(msg, raw_sig, self.obj)

class PrivateKey(object):

	def __init__(self, privkey=None, raw=True, flags=None, ctx=None):	
		if USE_SECP:
			if flags == None:
				flags = secp256k1.ALL_FLAGS
			self.obj = secp256k1.PrivateKey(privkey, raw, flags, ctx)
			self.pubkey = self.obj.pubkey
		else:
			if not raw:
				raise Exception("Non raw init unsupported")
			if privkey == None:
				privkey = ecpy.ecrand.rnd(CURVE_SECP256K1.order)
			else:
				privkey = int.from_bytes(privkey,'big')
			self.obj = ECPrivateKey(privkey, CURVE_SECP256K1)
			pubkey = self.obj.get_public_key().W
			out = b"\x04"
			out += pubkey.x.to_bytes(32, 'big')
			out += pubkey.y.to_bytes(32, 'big')
			self.pubkey = PublicKey(out, raw=True)

	def serialize(self):
		if USE_SECP:
			return self.obj.serialize()
		else:
			return "%.64x"%self.obj.d

	def ecdsa_serialize(self, raw_sig):
		if USE_SECP:
			return self.obj.ecdsa_serialize(raw_sig)
		else:
			return raw_sig		

	def ecdsa_sign(self, msg, raw=False, digest=hashlib.sha256):	
		if USE_SECP:
			return self.obj.ecdsa_sign(msg, raw, digest)
		else:
			if not raw:
				h = digest()
				h.update(msg)
				msg = h.digest()
			signature = SIGNER.sign(msg, self.obj)
			return bytearray(signature)
