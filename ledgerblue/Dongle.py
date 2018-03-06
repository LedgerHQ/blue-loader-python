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
from abc import ABCMeta, abstractmethod
from binascii import hexlify
import sys

TIMEOUT=20000

def hexstr(bstr):
	if (sys.version_info.major == 3):
		return hexlify(bstr).decode()
	if (sys.version_info.major == 2):
		return hexlify(bstr)
	return "<undecoded APDU<"

class DongleWait(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def waitFirstResponse(self, timeout):
		pass

class Dongle(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def exchange(self, apdu, timeout=TIMEOUT):
		pass

	@abstractmethod
	def apduMaxDataSize(self):
		pass

	@abstractmethod
	def close(self):
		pass

	def setWaitImpl(self, waitImpl):
		self.waitImpl = waitImpl