import asyncio
from bleak import BleakScanner, BleakClient
import bluetooth
import tkinter as tk
import requests

class BluetoothDevice:
    def __init__(self, address, name, device_type="Unknown", device_class="Unknown", vendor="Unknown", bluetooth_version="Unknown"):
        self.address = address
        self.name = name
        self.device_type = device_type
        self.device_class = device_class
        self.services = []  # Placeholder for services
        self.connected = False  # Flag to track connection status
        self.vendor = vendor  # Vendor information
        self.bluetooth_version = bluetooth_version  # Bluetooth version information

    def __str__(self):
        return f"Address: {self.address}, Name: {self.name}, Type: {self.device_type}, Class: {self.device_class}, Vendor: {self.vendor}, Version: {self.bluetooth_version}, Services: {self.services}, Connected: {self.connected}"

class BluetoothAnalyzer(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.pack()

        # Create UI elements
        self.scan_button = tk.Button(self, text="Scan for Devices", command=self.start_scanning)
        self.scan_button.pack()
        self.device_listbox = tk.Listbox(self, width=80, height=20, selectmode=tk.SINGLE)
        self.device_listbox.pack()
        self.connect_button = tk.Button(self, text="Connect to Selected Device", command=self.connect_to_selected_device)
        self.connect_button.pack()
        self.vulnerability_button = tk.Button(self, text="Check Vulnerabilities", command=self.check_vulnerabilities)
        self.vulnerability_button.pack()
        self.status_label = tk.Label(self, text="Status: Idle")
        self.status_label.pack()

        self.scanning = False  # Flag to track scanning state
        self.devices = []  # List to store scanned devices
        self.wireshark_running = False  # Flag to track Wireshark capture state

    async def get_services(self, device):
        async with BleakClient(device.address) as client:
            services = await client.get_services()
            return [service.uuid for service in services]

    async def scan_devices(self):
        self.device_listbox.delete(0, tk.END)  # Clear previous device list
        self.scanning = True
        self.update_status("Scanning...")

        try:
            # Run BLE and Classic scans concurrently
            ble_task = asyncio.create_task(self.scan_ble_devices())
            classic_task = asyncio.create_task(self.scan_classic_devices(num_scans=3))
            tasks = [ble_task, classic_task]

            # Wait for both scans to complete
            for task in asyncio.as_completed(tasks):
                devices = await task
                for device in devices:
                    # Fetch vendor information for each device
                    vendor = await self.get_mac_vendor(device.address)
                    device.vendor = vendor
                    # Fetch Bluetooth version for each device
                    bluetooth_version = await self.get_bluetooth_version(device.address)
                    device.bluetooth_version = bluetooth_version
                    # Fetch services for BLE devices
                    if device.device_type == "BLE":
                        services = await self.get_services(device)
                        device.services = services
                    self.devices.append(device)
                    self.device_listbox.insert(tk.END, f"{device.name} - {device.address} ({vendor}), Version: {device.bluetooth_version}")
        except Exception as e:  # Handle potential exceptions during scanning
            print(f"Error during scanning: {e}")
            self.update_status("Scan Error")
        finally:
            self.scanning = False  # Reset scanning state
            self.update_status("Idle")

    def check_vulnerabilities(self):
        selected_index = self.device_listbox.curselection()
        if selected_index:
            selected_device = self.devices[selected_index[0]]
            vendor_name = selected_device.vendor
            print(f"Checking vulnerabilities for {vendor_name}")
        # Implement your vulnerability checks here based on the vendor's name
            vulnerabilities = [
                {"vendor_name": "Infinix mobility limited", "vulnerability": "www.cvedetails.com/cve/CVE-2021-25427/"},
                {"vendor_name": "Antailiye Technology Co.,Ltd", "vulnerability": "www.example.com/vulnerability-list"},
            # Add more vulnerabilities for other vendors
                ]

        # Check if the selected device is vulnerable
            found_vulnerabilities = False
            for vuln in vulnerabilities:
                if vendor_name.upper() == vuln["vendor_name"].upper():
                    print(f"Vulnerability found: {vuln['vulnerability']}")
                    found_vulnerabilities = True
            if not found_vulnerabilities:
                print("No vulnerabilities found for this vendor.")
        else:
            print("No device selected.")

    def update_status(self, status):
        self.status_label.config(text=f"Status: {status}")
        self.status_label.update()

    def start_scanning(self):
        if not self.scanning:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.scan_devices())  # Run scan task asynchronously

    async def scan_ble_devices(self):
        devices = await BleakScanner.discover()
        ble_devices = []
        '''for device in devices:
            major_class = None
            minor_class = None
            try:
                advertisement_data = device.metadata.AdvertisementData

                if 'class' in advertisement_data:
                    major_class = (advertisement_data['class'] >> 8) & 0xff
                    minor_class = (advertisement_data['class'] >> 2) & 0x3f
                    version = None
                    if major_class == 0x01:  # Device is a Computer
                        if minor_class == 0x01:  # Minor class is a Desktop workstation
                            version = "Bluetooth 1.0b"
                        elif minor_class == 0x02:  # Minor class is a Server-class computer
                            version = "Bluetooth 1.1"
                        elif minor_class == 0x03:  # Minor class is a Laptop
                            version = "Bluetooth 1.2"
                    # Add more conditions for other minor classes if needed
                    elif major_class == 0x02:  # Device is a Phone
                        version = "Bluetooth 1.2"
                    elif major_class == 0x04:  # Device is a Audio/Video Device
                        version = "Bluetooth 1.2"
                    # Add more conditions for other major classes if needed
                    ble_devices.append(BluetoothDevice(device.address, device.name, "BLE", f"{major_class}.{minor_class}", vendor="Unknown", bluetooth_version=version))
            except Exception as e:
                print(f"Error processing BLE device: {e}, Major Class: {major_class}, Minor Class: {minor_class}")'''
        return ble_devices

    async def scan_classic_devices(self, num_scans=3):
        classic_devices = []
        for i in range(num_scans):
            nearby_devices = bluetooth.discover_devices(lookup_names=True)
            for addr, name in nearby_devices:
                classic_devices.append(BluetoothDevice(addr, name, "Classic Bluetooth"))
        return classic_devices

    async def get_mac_vendor(self, mac_address):
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_address}")
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown"
        except Exception as e:
            print(f"Error fetching vendor for {mac_address}: {e}")
            return "Unknown"

    async def get_bluetooth_version(self, mac_address):
        # Implement your logic to fetch Bluetooth version for a given MAC address
        return "Unknown"

    def connect_to_selected_device(self):
        selected_index = self.device_listbox.curselection()
        if selected_index:
            selected_device = self.devices[selected_index[0]]
            if not selected_device.connected:
                asyncio.run(self.connect_to_device(selected_device))
            else:
                print("Device is already connected.")
        else:
            print("No device selected.")

    async def connect_to_device(self, device):
        self.update_status(f"Connecting to {device.name}...")
        try:
            # Connection logic based on device type
            if device.device_type == "BLE":
                async with BleakClient(device.address) as client:
                    # Perform operations on the BLE device (e.g., read characteristics)
                    print(f"Connected to BLE device: {device.name} - {device.address}")
                    # You can add specific BLE communication code here (e.g., using GATT)
            elif device.device_type == "Classic Bluetooth":
                port = 1  # Replace with the appropriate service port for your device
                sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                sock.connect((device.address, port))
                print(f"Connected to Classic Bluetooth device: {device.name} - {device.address}")
                # You can add specific Classic Bluetooth communication code here (e.g., sending/receiving data)
                sock.close()
            else:
                print(f"Unsupported device type: {device.device_type}")
        except Exception as e:
            print(f"Error connecting to {device.name} - {device.address}: {e}")
        finally:
            self.update_status("Idle")  # Update status regardless of success or failure

    def update_status(self, status):
        self.status_label.config(text=f"Status: {status}")
        self.status_label.update()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Bluetooth Security Analyzer")
    app = BluetoothAnalyzer(root)
    root.mainloop()
