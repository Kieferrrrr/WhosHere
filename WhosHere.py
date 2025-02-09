# WhosHere
# Version 1.0
# https://github.com/kieferrrrr/whoshere

import os
import sys
import csv
import time
import socket
import datetime
import subprocess

try: # Modules which need installing
    import psutil # Couldnt use netifaces on Python3.12
    import configparser
    from scapy.all import ARP, Ether, srp
    from colorama import just_fix_windows_console
except ImportError as missingModule:
    print(f" Required module {missingModule} is not installed\n     run pip install -r requirements. txt")


__version__ = "1.0"

# Required to fix ANSI color code issues within some windows terminals
if sys.platform == "win32":
    cl = "cls"
    just_fix_windows_console()
elif sys.platform.startswith("linux"):
    cl = "clear"
    if os.getuid != 0:
        sys.exit(" Must be sudo to run WhosHere on linux\n     run sudo WhosHere.py")
else:
    print(errs[3], end="\r")

# ANSI color codes
white = "\x1b[38;5;254m"  # Text
grey = "\x1b[38;5;245m"   # Events and info
blue = "\x1b[38;5;45m"    # Variables
amber = "\x1b[38;5;220m"  # Errors
red = "\x1b[38;5;196m"    # Fatal errors
orange = "\x1b[38;5;202m" # Table headers

banner = f"""{white}     
 ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
 ██  ████  █  █████▀▀▀██▀▀▀▀█  ██  ██▀▀▀▀██▀▀▀██▀▀▀▀██  Local Network Scanner
 ██  ▀  ▀  █  ▀▀▀█  █  █  ▀▀█      █  ▀▀▄█  ▄██  ▀▀▄██  Version {__version__}
 ███  ▄▄  ██  █  █▄ ▀ ▄█▀▀  █  ██  █▄ ▀▀██  ███▄ ▀▀███  https://github.com/kieferrrrr/whoshere 
 ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""

whDir = f"{os.path.dirname(os.path.realpath(__file__))}/" # Full directory of the WhosHere.py file
whDir = whDir.replace("\\", "/") # Fixing directories such as "C:\Users\test\Desktop\WhosHere/logs"

# Dict of predictable errors
errs = {
    1: "CTRL+C pressed", # Keyboard interrupt pressed in terminal
    2: "Cannot import WhosHere.py as a module", # WhosHere.py is not a module
    3: "Operating system could not be defined", # sys.platform didnt find windows or basic linux
    4: "Failed to find config.ini", # config.ini is not in its expected path
    5: "Failed to find or use value in config.ini", # A value in config.ini is missing or unusable
    6: "Unknown", # Failed to fetch ssid or hostname
    7: "Interface could not be used" # Set interface or default interface could not be used
}


# Broad spectrum error message controller for simple errors
def throwErr(err, fatal: bool):
    if not fatal:
        print(f" {white}[{amber}Error{white}] {err}")
    if fatal: # Controlled exit for fatal errors
        print(f" {white}[{amber}Error{white}]-[{red}Fatal{white}] {err}\n")
        sys.exit()


class main:
    def __init__(self):
        self.ssid = None
        self.subnetMask = None
        self.cidr = 0
        self.ip = None
        self.devices = []
        # Default configs in the event of a fail reading from config.ini
        self.saveScan = False
        self.liveScan = False
        self.liveScanDelay = 30
        self.setInterface = None

    def getINI(self):
        try:
            conf = configparser.ConfigParser()
            conf.read(f"{whDir}config.ini")
            try:
                self.saveScan = bool(conf["CONFIG"]["saveScan"])
                self.liveScan = bool(conf["CONFIG"]["liveScan"])
                self.liveScanDelay = int(conf["CONFIG"]["liveScanDelay"])
                self.setInterface = conf["CONFIG"]["setInterface"]
                if self.setInterface == "None":
                    self.setInterface = None
            except configparser.Error:
                throwErr(errs[5], fatal=False)
        except FileNotFoundError:
            throwErr(errs[4], fatal=False)

    def getSSID(self): # get SSID
        try:
            if sys.platform == "win32":
                self.ssid = subprocess.check_output(f"powershell.exe (Get-NetConnectionProfile).Name", shell=True).decode().strip()
            elif sys.platform == "linux":
                self.ssid = subprocess.check_output("iwgetid -r", shell=True).decode().strip()
        except:
            pass
        if self.ssid == None:
            self.ssid = errs[6]

    def scanNetwork(self): # Retrieve subnetmask, cidr and connected device ip, mac, hostname
        netInfo = psutil.net_if_addrs()
        if self.setInterface == None:
            if sys.platform == "win32":
                self.setInterface = "Wi-Fi"
            if sys.platform.startswith("linux"):
                interfaceStats = psutil.net_if_stats()
                for interface, stats in interfaceStats.items():
                    if interface.startswith("wl"): # Attempt to catch a wirless interface wlan0 or wlp2s0
                        self.setInterface = interface
                        break
        # Get the subnet mask
        if self.setInterface is not None and self.setInterface in netInfo:
            for addr in netInfo[self.setInterface]:
                if addr.family == socket.AF_INET and not addr.address.startswith("127"):
                    self.subnetMask = addr.netmask
                    self.ip = addr.address
        else:
            throwErr(errs[7], fatal=True)
        # Resolve the cidr notation from the subnet mask
        subnetMaskSegments = self.subnetMask.split(".")
        for segment in subnetMaskSegments:
            segmentBinary = format(int(segment), "b")
            for bit in segmentBinary:
                if bit == "1":
                    self.cidr = self.cidr + 1
        # Scanning the networks connected devices
        arp = ARP(pdst=f"{self.ip}/{self.cidr}")
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp
        answered = srp(packet, timeout=2, verbose=False)[0]
        for sent, recieved in answered:
            ip = recieved.psrc
            mac = recieved.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.error:
                hostname = errs[6]
            self.devices.append({"IP": ip, "Mac": mac, "Hostname": hostname})

    def printConnInfo(self): # print network connection info
        print(f"\n  {orange}{'SSID':<20}{'Subnet Mask':<20}{'CIDR':<10}{'Interface':<10}{white}")
        print(f" +{'-'*60}+") # Was 44 before added interface
        print(f"  {self.ssid:<20}{self.subnetMask:<20}{str(self.cidr):<10}{self.setInterface:<10}\n")

    def printScanInfo(self): # print scan results
        print(f"  {orange}{'IP Address':<20}{'Mac Address':<20}{'Hostname':<20}{white}")
        print(f" +{'-'*60}+")
        for device in self.devices:
            print(f"  {device["IP"]:<20}{device["Mac"]:<20}{device["Hostname"]:<20}")

    # Write scan logs to a csv file in ./logs
    def writeCSV(self):
        cDate = datetime.datetime.now().strftime("%d-%m-%y")
        cTime = datetime.datetime.now().strftime("%H-%M-%S")
        if os.path.exists(f"{whDir}logs/{cDate}") == False:
            os.mkdir(f"{whDir}logs/{cDate}")
        with open(f"{whDir}logs/{cDate}/{cTime}.csv", mode="w", newline="") as file:
            writer = csv.writer(file)
            for device in self.devices:
                line = device["IP"], device["Mac"], device["Hostname"]
                writer.writerow(line)
            print(f"\n {white}[{grey}Info]{white} Scan results saved to {blue}logs/{cDate}/{cTime}.csv{white}")

    def main(self):
        print(banner)
        self.getINI()        # Load configurations from config.ini
        self.scanNetwork()   # Retrieve the subnet mask and cidr then scan the network 
        self.getSSID()       # Retrieve the connected networks ssid
        self.printConnInfo() # Print the ssid, subnet mask and cidr
        self.printScanInfo() # Print the scan results
        if self.saveScan == True:
            self.writeCSV()
        if self.liveScan == True:
            countdown = self.liveScanDelay
            while countdown > 0:
                print(f" {white}[{grey}Info{white}] Re-scanning in {blue}{countdown}{white} seconds", end="\r", flush=True)
                countdown = countdown - 1
                time.sleep(1)
            os.system(cl)
            main().main()
        else:
            sys.exit("\n")


if __name__ == "__main__":
    try:
        main().main()
    except KeyboardInterrupt:
        throwErr(errs[1], fatal=True)
else:
    throwErr(errs[2], fatal=True)