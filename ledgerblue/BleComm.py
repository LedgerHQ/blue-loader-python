import asyncio
import argparse
import os
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

LEDGER_SERVICE_UUID = "13d63400-2c97-6004-0000-4c6564676572"

def get_argparser():
    parser = argparse.ArgumentParser(description="Manage ledger ble devices.")
    parser.add_argument("--show", help="Show currently selected ledger device.", action='store_true')
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

if __name__ == "__main__":
    args = get_argparser().parse_args()
    try:
        if args.show:
            print(f"Environment variable LEDGER_BLE_MAC currently set to '{os.environ['LEDGER_BLE_MAC']}'")
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
    
