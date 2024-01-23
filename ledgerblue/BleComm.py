import asyncio
import argparse
import os
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from typing import List

LEDGER_SERVICE_UUID_STAX = "13d63400-2c97-6004-0000-4c6564676572"
LEDGER_SERVICE_UUID_NANOX = "13d63400-2c97-0004-0000-4c6564676572"

TAG_ID = b"\x05"

def get_argparser():
    parser = argparse.ArgumentParser(description="Manage ledger ble devices.")
    parser.add_argument("--show", help="Show currently selected ledger device.", action='store_true')
    parser.add_argument("--demo", help="Get version demo (connect to ble device, send get version, print response and disconnect).", action='store_true')
    return parser

class NoLedgerDeviceDetected(Exception):
    pass

class BleScanner(object):
    def __init__(self):
        self.devices = []

    def __scan_callback(self, device: BLEDevice, advertisement_data: AdvertisementData):
        if LEDGER_SERVICE_UUID_STAX in advertisement_data.service_uuids or LEDGER_SERVICE_UUID_NANOX in advertisement_data.service_uuids:
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

    characteristic_notify = None
    characteristic_write_with_rsp = None
    characteristic_write_cmd = None
    for service in client.services:
        if service.uuid in [LEDGER_SERVICE_UUID_NANOX, LEDGER_SERVICE_UUID_STAX]:
            for char in service.characteristics:
                if "0001" in char.uuid:
                    characteristic_notify = char
                if "0002" in char.uuid:
                    characteristic_write_with_rsp = char
                if "0003" in char.uuid:
                    characteristic_write_cmd = char

    assert characteristic_notify != None

    # Choose write cmd to speed up transfers
    characteristic_write = characteristic_write_cmd
    if characteristic_write == None:
        characteristic_write = characteristic_write_with_rsp

    # Register notifications callback
    await client.start_notify(characteristic_notify, callback)

    # Enable notifications
    await client.write_gatt_char(characteristic_write.uuid, bytes.fromhex("0001"))
    assert await queue.get() == b"\x00\x00\x00\x00\x00"

    # Get MTU value
    await client.write_gatt_char(characteristic_write.uuid, bytes.fromhex("0800000000"))
    response = await queue.get()
    mtu = int.from_bytes(response[5:6], 'big')

    print("[BLE] MTU {:d}".format(mtu))

    return client, mtu, characteristic_write

async def _read(mtu) -> bytes:
    response = await queue.get()
    assert len(response) >= 5
    assert response[0] == TAG_ID[0]
    sequence = int.from_bytes(response[1:3], 'big')
    assert sequence == 0
    total_size = int.from_bytes(response[3:5], "big")

    total_size_bkup = total_size
    if total_size >= (mtu-5):
        apdu = response[5:mtu]
        total_size -= (mtu-5)

        response = await queue.get()
        assert response[0] == TAG_ID[0]
        assert len(response) >= 3
        next_sequence = int.from_bytes(response[1:3], 'big')
        assert next_sequence == sequence+1
        sequence = next_sequence

        while total_size >= (mtu-3):
            apdu += response[3:mtu]
            total_size -= (mtu-3)
            response = await queue.get()
            assert response[0] == TAG_ID[0]
            assert len(response) >= 3
            sequence = int.from_bytes(response[1:3], 'big')
            assert next_sequence == sequence+1
            sequence = next_sequence

        if total_size > 0:
            apdu += response[3:3+total_size]
    else:
        apdu = response[5:]

    assert len(apdu) == total_size_bkup
    return apdu


async def _write(client: BleakClient, data: bytes, write_characteristic, mtu: int = 20):
    chunks: List[bytes] = []
    buffer = data
    while buffer:
        if not chunks:
            size = 5
        else:
            size = 3
        size = mtu - size
        chunks.append(buffer[:size])
        buffer = buffer[size:]

    for i, chunk in enumerate(chunks):
        header = TAG_ID
        header += i.to_bytes(2, "big")
        if i == 0:
            header += len(data).to_bytes(2, "big")
        await client.write_gatt_char(write_characteristic.uuid, header + chunk)


class BleDevice(object):
    def __init__(self, address):
        self.address = address
        self.loop = None
        self.client = None
        self.opened = False
        self.mtu = 20
        self.write_characteristic = None

    def open(self):
        self.loop = asyncio.new_event_loop()
        self.client, self.mtu, self.write_characteristic = self.loop.run_until_complete(_get_client(self.address))
        self.opened = True

    def close(self):
        if self.opened:
            self.loop.run_until_complete(self.client.disconnect())
            self.opened = False
            self.loop.close()

    def __write(self, data: bytes):
        self.loop.run_until_complete(_write(self.client, data, self.write_characteristic, self.mtu))

    def __read(self) -> bytes:
        return self.loop.run_until_complete(_read(self.mtu))

    def exchange(self, data: bytes, timeout=1000) -> bytes:
        self.__write(data)
        return self.__read()

if __name__ == "__main__":
    args = get_argparser().parse_args()
    try:
        if args.show:
            print(f"Environment variable LEDGER_BLE_MAC currently set to '{os.environ['LEDGER_BLE_MAC']}'")
        elif args.demo:
            try:
                ble_device = BleDevice(os.environ['LEDGER_BLE_MAC'])
            except Exception as ex:
                print(f"Please run 'python -m ledgerblue.BleComm' to select wich device to connect to")
                raise ex
            print("-----------------------------Get version BLE demo------------------------------")
            ble_device.open()
            print(f"Connected to {ble_device.address}")
            get_version_apdu = bytes.fromhex("e001000000")
            print(f"[BLE] => {get_version_apdu.hex()}")
            result = ble_device.exchange(get_version_apdu)
            print(f"[BLE] <= {result.hex()}")
            ble_device.close()
            print(f"Disconnected from {ble_device.address}")
            print(79*"-")
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
                print(f"Please run 'export LEDGER_BLE_MAC=\"{scanner.devices[index-1][0]}\"' to select which device to connect to")
            else:
                raise NoLedgerDeviceDetected
    except NoLedgerDeviceDetected as ex:
        print(ex)
    except Exception as ex:
        raise ex

