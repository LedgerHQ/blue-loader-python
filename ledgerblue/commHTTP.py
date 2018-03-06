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
from .commException import CommException
from .ledgerWrapper import wrapCommandAPDU, unwrapResponseAPDU
from binascii import hexlify
import time
import os
import sys
import requests
import json

def hexstr(bstr):
	if (sys.version_info.major == 3):
		return hexlify(bstr).decode()
	if (sys.version_info.major == 2):
		return hexlify(bstr)
	return "<undecoded APDU<"


class HTTPProxy(object):

    def __init__(self, remote_host="localhost:8081", debug=False):
        self.remote_host = "http://" + remote_host
        self.debug = debug


    def exchange(self, apdu):
        if self.debug:
            print("=> %s" % hexstr(apdu))
    
        try:
            ret = requests.post(self.remote_host + "/send_apdu", params={"data": hexstr(apdu)})

            while True:
                ret = requests.post(self.remote_host + "/fetch_apdu")
                if ret.text != "no response apdu yet":
                    print("<= %s" % ret.text)
                    break
                else:
                    time.sleep(0.1)


            return bytearray(str(ret.text).decode("hex"))
        except Exception as e:
            print(e)



    def exchange_seph_event(self, event):
        if self.debug >= 3:
            print("=> %s" % hexstr(event))

        try:
            ret = requests.post(self.remote_host + "/send_seph_event", params={"data": event.encode("hex")})
            return ret.text
        except Exception as e:
            print(e)


    def poll_status(self):
        if self.debug >= 5:
            print("=> Waiting for a status")

        try:
            while True:
                ret = requests.post(self.remote_host + "/fetch_status")
                if ret.text != "no status yet":
                    break
                else:
                    time.sleep(0.05)

            return bytearray(str(ret.text).decode("hex"))
        except Exception as e:
            print(e)


    def reset(self):
        if self.debug:
            print("=> Reset")

        try:
            ret = requests.post(self.remote_host + "/reset")
        except Exception as e:
            print(e)







def getDongle(remote_host="localhost", debug=False):

    return HTTPProxy(remote_host, debug)