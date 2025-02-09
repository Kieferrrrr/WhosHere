# WhosHere
Local network scanner written in Python3
![demo](https://github.com/user-attachments/assets/82c8287f-a0a9-471d-9793-d77990b8024f)

## Description
WhosHere is a simple network scanner for retrieving the IP addresses, MAC addresses and hostnames of all devices connected to your network. Although primarily designed for network troubleshooting, WhosHere could be used for network security and monitoring.

## Installation and Running
```shell
git clone https://github.com/kiefer/kieferrrrr/whoshere
cd whoshere
pip install -r requirements.txt
python WhosHere.py
```
### Configuration
WhosHere comes with a configuration file called config.ini which contains various options the user can alter in order to tune the network scanning to their preference or need.

| Config        | Value      |  Description |
|---------------|------------|--------------|
| saveScan      | True/False | Choose whether to save scan results to a .csv file or not |
| liveScan      | True/False | Enable recurring scans using a set delay between them |
| liveScanDelay | Int        | Set the delay between recurring scans |
| setInterface  | Str        | Use a specific network interface rather than system default |
