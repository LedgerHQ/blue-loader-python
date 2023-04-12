import asyncio
import argparse
import os
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

LEDGER_SERVICE_UUID = "13d63400-2c97-6004-0000-4c6564676572"
HANDLE_CHAR_ENABLE_NOTIF = 13
HANDLE_CHAR_WRITE = 16

def get_argparser():
    parser = argparse.ArgumentParser(description="Manage ledger ble devices.")
    parser.add_argument("--show", help="Show currently selected ledger device.", action='store_true')
    parser.add_argument("--demo", help="Connect/Disconnect demo.", action='store_true')
    return parser

class NoLedgerDeviceDetected(Exception):
    pass

class BleScanner(object):
    def __init__(self):
        self.devices = []        
    
    def __scan_callback(self, device: BLEDevice, advertisement_data: AdvertisementData):
        if LEDGER_SERVICE_UUID in advertisement_data.service_uuids:
            device_is_in_list = False
            for dev in self.devices:
                if device.address == dev[0]:
                    device_is_in_list = True
            if not device_is_in_list:
                self.devices.append((device.address, device.name))

    async def scan(self):
        scanner = BleakScanner(
            self.__scan_callback,
        )
        await scanner.start()
        counter = 0
        while counter < 50:
            await asyncio.sleep(0.01)
            counter += 1
        await scanner.stop()

queue: asyncio.Queue = asyncio.Queue()

def callback(sender, data):
    response = bytes(data)
    queue.put_nowait(response)

async def _get_client(address: str) -> BleakClient:
    # Connect to client
    client = BleakClient(address)
    await client.connect()

    # Register notifications callback
    await client.start_notify(HANDLE_CHAR_ENABLE_NOTIF, callback)

    # Enable notifications
    await client.write_gatt_char(HANDLE_CHAR_WRITE, bytes.fromhex("0001"), True)
    assert await queue.get() == b"\x00\x00\x00\x00\x00"

    # confirm that the MTU is 0x99
    await client.write_gatt_char(HANDLE_CHAR_WRITE, bytes.fromhex("0800000000"), True)
    assert await queue.get() == b"\x08\x00\x00\x00\x01\x99"

    return client

class BleDevice(object):
    def __init__(self, address):
        self.address = address
        self.loop = None
        self.client = None
        self.opened = False

    def open(self):
        self.loop = asyncio.get_event_loop()
        self.client = self.loop.run_until_complete(_get_client(self.address))
        self.opened = True

    def close(self):
        if self.opened:
            self.loop = asyncio.get_event_loop()
            self.loop.run_until_complete(self.client.disconnect())
            self.opened = False
            self.loop.close()

if __name__ == "__main__":
    args = get_argparser().parse_args()
    try:
        if args.show:
            print(f"Environment variable LEDGER_BLE_MAC currently set to '{os.environ['LEDGER_BLE_MAC']}'")
        elif args.demo:
            ble_device = BleDevice(os.environ['LEDGER_BLE_MAC'])
            ble_device.open()
            ble_device.close()
        else:
            scanner = BleScanner()
            asyncio.run(scanner.scan())
            devices_str = ""
            device_idx = 0
            if len(scanner.devices):
                for device in scanner.devices:
                    devices_str += f"  -{device_idx+1}- mac=\"{device[0]}\" name=\"{device[1]}\"\n"
                    device_idx += 1
                index = int(input(f"Select device by index\n{devices_str}"))
                os.environ['LEDGER_BLE_MAC']=scanner.devices[index-1][0]
                print(f"Environment variable LEDGER_BLE_MAC succesfully set to '{scanner.devices[index-1][0]}'")
            else:
                raise NoLedgerDeviceDetected
    except NoLedgerDeviceDetected as ex:
        print(ex)
    except Exception as ex:
        raise ex
    
