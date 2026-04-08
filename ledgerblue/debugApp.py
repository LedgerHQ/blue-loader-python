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

import argparse
import sys
import time
from datetime import datetime

import serial
import serial.tools.list_ports

LEDGER_VENDOR_ID = 0x2C97


def get_argparser():
    parser = argparse.ArgumentParser(
        description="Listen to debug output from a Ledger app compiled with DEBUG_OVER_USB."
    )
    parser.add_argument(
        "--port", "-p",
        help="Serial port to use (e.g. COM3 on Windows, /dev/ttyACM0 on Linux). Auto-detected if omitted.",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--baudrate", "-b",
        help="Baud rate for the serial connection (default: 115200).",
        type=int,
        default=115200,
    )
    parser.add_argument(
        "--output", "-o",
        help="Write debug output to a file in addition to stdout.",
        type=str,
        default=None,
    )
    return parser


def find_ledger_cdc_port(port=None):
    """Find the Ledger device's CDC (virtual serial) port.

    When DEBUG_OVER_USB is enabled in a Ledger app, the device exposes
    an additional USB CDC interface that sends PRINTF debug output.
    """
    if port:
        return port

    for p in serial.tools.list_ports.comports():
        if p.vid == LEDGER_VENDOR_ID:
            return p.device

    return None


def wait_for_cdc_port(port=None, timeout=0):
    """Wait for the Ledger CDC port to appear.

    If timeout is 0, wait indefinitely.
    Returns the port name, or None if timeout expired.
    """
    start = time.time()
    first = True
    while True:
        cdc_port = find_ledger_cdc_port(port)
        if cdc_port is not None:
            if not first:
                sys.stdout.write("\n")
                sys.stdout.flush()
            return cdc_port
        if first:
            print("Waiting for Ledger CDC debug port...", end="", flush=True)
            first = False
        else:
            sys.stdout.write(".")
            sys.stdout.flush()
        if timeout and (time.time() - start) >= timeout:
            sys.stdout.write("\n")
            sys.stdout.flush()
            return None
        time.sleep(1)


if __name__ == "__main__":
    args = get_argparser().parse_args()

    output_file = None
    if args.output:
        try:
            output_file = open(args.output, "a", encoding="utf-8")
        except OSError:
            print("Unable to open file {} for writing.".format(args.output))
            sys.exit(1)

    try:
        while True:
            cdc_port = wait_for_cdc_port(args.port)
            if cdc_port is None:
                print(
                    "No Ledger CDC debug port found.\n"
                    "Make sure your Ledger app was compiled with DEBUG_OVER_USB=1\n"
                    "and that the device is connected and the app is running.\n"
                    "You can also specify the port manually with --port."
                )
                sys.exit(1)

            print("Connected on {} (baudrate={}).".format(cdc_port, args.baudrate))
            print("Press Ctrl+C to stop.\n")

            try:
                with serial.Serial(cdc_port, args.baudrate, timeout=1) as ser:
                    while True:
                        data = ser.readline()
                        if data:
                            text = data.decode("utf-8", errors="replace")
                            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                            for line in text.splitlines(True):
                                stamped = "[{}] {}".format(timestamp, line)
                                sys.stdout.write(stamped)
                                sys.stdout.flush()
                                if output_file:
                                    output_file.write(stamped)
                                    output_file.flush()
            except serial.SerialException:
                print("\nSerial connection lost. Waiting for device...")
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if output_file:
            output_file.close()
