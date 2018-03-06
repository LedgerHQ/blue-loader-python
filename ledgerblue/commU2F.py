# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
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

import os
import traceback
from abc import ABCMeta, abstractmethod
from .ledgerWrapper import wrapCommandAPDU, unwrapResponseAPDU
from binascii import hexlify
from .Dongle import *

import binascii
import time
import sys
import hid
from u2flib_host.device import U2FDevice
from u2flib_host.yubicommon.compat import byte2int, int2byte
from u2flib_host.constants import INS_ENROLL, INS_SIGN
from u2flib_host import u2f, exc
from u2flib_host.utils import websafe_decode, websafe_encode
from hashlib import sha256

from .commException import CommException

TIMEOUT=30000

DEVICES = [
    (0x1050, 0x0200),  # Gnubby
    (0x1050, 0x0113),  # YubiKey NEO U2F
    (0x1050, 0x0114),  # YubiKey NEO OTP+U2F
    (0x1050, 0x0115),  # YubiKey NEO U2F+CCID
    (0x1050, 0x0116),  # YubiKey NEO OTP+U2F+CCID
    (0x1050, 0x0120),  # Security Key by Yubico
    (0x1050, 0x0410),  # YubiKey Plus
    (0x1050, 0x0402),  # YubiKey 4 U2F
    (0x1050, 0x0403),  # YubiKey 4 OTP+U2F
    (0x1050, 0x0406),  # YubiKey 4 U2F+CCID
    (0x1050, 0x0407),  # YubiKey 4 OTP+U2F+CCID
    (0x2581, 0xf1d0),  # Plug-Up U2F Security Key
    (0x2581, 0xf1d1),  # Ledger Production U2F Dongle
    (0x2c97, 0x0000),  # Ledger Blue
    (0x2c97, 0x0001),  # Ledger Nano S
    (0x2c97, 0x0002),  # Ledger Aramis
    (0x2c97, 0x0003),  # Ledger HW2
    (0x2c97, 0x0004),  # Ledger Blend
    (0x2c97, 0xf1d0),  # Plug-Up U2F Security Key
]
HID_RPT_SIZE = 64

TYPE_INIT = 0x80
U2F_VENDOR_FIRST = 0x40

CMD_INIT = 0x06
CMD_WINK = 0x08
CMD_APDU = 0x03
U2FHID_YUBIKEY_DEVICE_CONFIG = U2F_VENDOR_FIRST

STAT_ERR = 0xbf

def _read_timeout(dev, size, timeout=TIMEOUT):
    if (timeout > 0):
      timeout += time.time()
    while timeout == 0 or time.time() < timeout:
        resp = dev.read(size)
        if resp:
            return resp
        time.sleep(0.01)
    return []

class U2FHIDError(Exception):
    def __init__(self, code):
        super(Exception, self).__init__("U2FHIDError: 0x%02x" % code)
        self.code = code


class HIDDevice(U2FDevice):

    """
    U2FDevice implementation using the HID transport.
    """

    def __init__(self, path):
        self.path = path
        self.cid = b"\xff\xff\xff\xff"

    def open(self):
        self.handle = hid.device()
        self.handle.open_path(self.path)
        self.handle.set_nonblocking(True)
        self.init()

    def close(self):
        if hasattr(self, 'handle'):
            self.handle.close()
            del self.handle

    def init(self):
        nonce = os.urandom(8)
        resp = self.call(CMD_INIT, nonce)
        while resp[:8] != nonce:
            print("Wrong nonce, read again...")
            resp = self._read_resp(self.cid, CMD_INIT)
        self.cid = resp[8:12]

    def set_mode(self, mode):
        data = mode + b"\x0f\x00\x00"
        self.call(U2FHID_YUBIKEY_DEVICE_CONFIG, data)

    def _do_send_apdu(self, apdu_data):
        return self.call(CMD_APDU, apdu_data)

    def wink(self):
        self.call(CMD_WINK)

    def _send_req(self, cid, cmd, data):
        size = len(data)
        bc_l = int2byte(size & 0xff)
        bc_h = int2byte(size >> 8 & 0xff)
        payload = cid + int2byte(TYPE_INIT | cmd) + bc_h + bc_l + \
            data[:HID_RPT_SIZE - 7]
        payload += b'\0' * (HID_RPT_SIZE - len(payload))
        if self.handle.write([0] + [byte2int(c) for c in payload]) < 0:
          raise exc.DeviceError("Cannot write to device!")
        data = data[HID_RPT_SIZE - 7:]
        seq = 0
        while len(data) > 0:
            payload = cid + int2byte(0x7f & seq) + data[:HID_RPT_SIZE - 5]
            payload += b'\0' * (HID_RPT_SIZE - len(payload))
            if self.handle.write([0] + [byte2int(c) for c in payload]) < 0:
              raise exc.DeviceError("Cannot write to device!")
            data = data[HID_RPT_SIZE - 5:]
            seq += 1

    def _read_resp(self, cid, cmd):
        resp = b'.'
        header = cid + int2byte(TYPE_INIT | cmd)
        while resp and resp[:5] != header:
            # allow for timeout
            resp_vals = _read_timeout(self.handle, HID_RPT_SIZE)
            resp = b''.join(int2byte(v) for v in resp_vals)
            if resp[:5] == cid + int2byte(STAT_ERR):
                raise U2FHIDError(byte2int(resp[7]))

        if not resp:
            raise exc.DeviceError("Invalid response from device!")

        data_len = (byte2int(resp[5]) << 8) + byte2int(resp[6])
        data = resp[7:min(7 + data_len, HID_RPT_SIZE)]
        data_len -= len(data)

        seq = 0
        while data_len > 0:
            resp_vals = _read_timeout(self.handle, HID_RPT_SIZE)
            resp = b''.join(int2byte(v) for v in resp_vals)
            if resp[:4] != cid:
                raise exc.DeviceError("Wrong CID from device!")
            if byte2int(resp[4:5]) != seq & 0x7f:
                raise exc.DeviceError("Wrong SEQ from device!")
            seq += 1
            new_data = resp[5:min(5 + data_len, HID_RPT_SIZE)]
            data_len -= len(new_data)
            data += new_data
        return data

    def call(self, cmd, data=b''):
        if isinstance(data, int):
            data = int2byte(data)

        self._send_req(self.cid, cmd, data)
        return self._read_resp(self.cid, cmd)

class U2FTunnelDongle(Dongle, DongleWait):

  def __init__(self, device, scrambleKey="", ledger=False, debug=False):
    self.device = device
    self.scrambleKey = scrambleKey
    self.ledger = ledger    
    self.debug = debug
    self.waitImpl = self
    self.opened = True
    self.device.open()

  def exchange(self, apdu, timeout=TIMEOUT):
    if self.debug:
      print("U2F => %s" % hexstr(apdu))

    if (len(apdu)>=256):
      raise CommException("Too long APDU to transport")  
    
    # wrap apdu
    i=0
    keyHandle = ""
    while i < len(apdu):
      val = apdu[i:i+1]
      if len(self.scrambleKey) > 0:
        val = chr(ord(val) ^ ord(self.scrambleKey[i % len(self.scrambleKey)]))
      keyHandle += val
      i+=1
    
    client_param = sha256("u2f_tunnel".encode('utf8')).digest()
    app_param = sha256("u2f_tunnel".encode('utf8')).digest()

    request = client_param + app_param + int2byte(len(keyHandle)) + keyHandle

    #p1 = 0x07 if check_only else 0x03
    p1 = 0x03
    p2 = 0
    response = self.device.send_apdu(INS_SIGN, p1, p2, request)

    if self.debug:
      print("U2F <= %s%.2x" % (hexstr(response), 0x9000))

    # check replied status words of the command (within the APDU tunnel)
    if hexstr(response[-2:]) != "9000":
      raise CommException("Invalid status words received: " + hexstr(response[-2:]));

    # api expect a byte array, remove the appended status words
    return bytearray(response[:-2])

  def apduMaxDataSize(self):
    return 256-5

  def close(self):
  	self.device.close()

  def waitFirstResponse(self, timeout):
  	raise CommException("Invalid use")

def getDongles(dev_class=None, scrambleKey="", debug=False):
    dev_class = dev_class or HIDDevice
    devices = []
    for d in hid.enumerate(0, 0):
        usage_page = d['usage_page']
        if usage_page == 0xf1d0 and d['usage'] == 1:
            devices.append(U2FTunnelDongle(dev_class(d['path']),scrambleKey, debug=debug))
        # Usage page doesn't work on Linux
        # well known devices
        elif (d['vendor_id'], d['product_id']) in DEVICES:
            device = HIDDevice(d['path'])
            try:
                device.open()
                device.close()
                devices.append(U2FTunnelDongle(dev_class(d['path']),scrambleKey, debug=debug))
            except (exc.DeviceError, IOError, OSError):
                pass
        # unknown devices
        else:
            device = HIDDevice(d['path'])
            try:
                device.open()
                # try a ping command to ensure a FIDO device, else timeout (BEST here, modulate the timeout, 2 seconds is way too big)
                device.ping()
                device.close()
                devices.append(U2FTunnelDongle(dev_class(d['path']),scrambleKey, debug=debug))
            except (exc.DeviceError, IOError, OSError):
                pass
    return devices

def getDongle(path=None, dev_class=None, scrambleKey="", debug=False):
  # if path is none, then use the first device
  dev_class = dev_class or HIDDevice
  devices = []
  for d in hid.enumerate(0, 0):
    if path is None or d['path'] == path:
      usage_page = d['usage_page']
      if usage_page == 0xf1d0 and d['usage'] == 1:
          return U2FTunnelDongle(dev_class(d['path']),scrambleKey, debug=debug)
      # Usage page doesn't work on Linux
      # well known devices
      elif (d['vendor_id'], d['product_id']) in DEVICES and ('interface_number' not in d or d['interface_number'] == 1):
          #print d
          device = HIDDevice(d['path'])
          try:
              device.open()
              device.close()
              return U2FTunnelDongle(dev_class(d['path']),scrambleKey, debug=debug)
          except (exc.DeviceError, IOError, OSError):
              traceback.print_exc()
              pass
      # unknown devices
      # else:
      #     device = HIDDevice(d['path'])
      #     try:
      #         device.open()
      #         # try a ping command to ensure a FIDO device, else timeout (BEST here, modulate the timeout, 2 seconds is way too big)
      #         device.ping()
      #         device.close()
      #         return U2FTunnelDongle(dev_class(d['path']),scrambleKey, debug=debug)
      #     except (exc.DeviceError, IOError, OSError):
      #         traceback.print_exc()
      #         pass
  raise CommException("No dongle found")
