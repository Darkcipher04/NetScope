# NetScope
"NetScope - Network Analyzer &amp; Packet Sniffer," presents the design and  implementation of a real-time network traffic analysis tool developed using Python. The application captures live network packets traversing through a selected network interface, decodes them according to TCP/IP protocol stack and presents information in an intuitive (GUI).

## Hardware & Operating System Requirements
Recommended Specification\
OS - Windows 10 or Windows 11 (64-bit)\
Privileges - Administrator Access (Required for raw socket packet capturing)\
RAM	4 GB minimum (8 GB recommended)\
Network Interface	Active Wi-Fi or Ethernet Card

## Software Prerequisites
#### A. Npcap Packet Capture Driver (Crucial for Windows)
What it is: The packet capture engine required by Scapy on Windows.\
Download Link: https://npcap.com/#download\
Installation Notice: During installation, MUST check the box:\
[x] Install Npcap in WinPcap API-compatible Mode
#### B. Python Runtime
Recommended Version: Python 3.12.x (64-bit) or Python 3.11.x (official release from python.org).\
Note: Avoid pre-release versions (like 3.14.0) to prevent C-extension binary compatibility errors with Matplotlib/Scapy.\
Installation Option: During setup, check [x] Add python.exe to PATH.

## Complete Step-by-Step Setup Guide

### Step 1: Install Npcap Driver
Download npcap-1.79.exe (or latest) from npcap.com.\
Run installer → check "Install Npcap in WinPcap API-compatible Mode" → Complete setup.
### Step 2: Open VS Code as Administrator
Close VS Code.\
Click Start Menu → search VS Code.\
Right-click Visual Studio Code → Select Run as Administrator.\
Open folder: C:\Users\Ramthakur\NetScope.\
### Step 3: Create & Activate Virtual Environment\
Open terminal in VS Code (Ctrl + ~) and run: PowerShell

#### 1. Create virtual environment
python -m venv venv

#### 2. Activate virtual environment
.\venv\Scripts\activate

#### 3. Upgrade pip
python -m pip install --upgrade pip

#### 4. Install all required packages
pip install scapy matplotlib psutil Pillow requests

### Step 4: Run NetScope
PowerShell\
python main.py

### Run VS Code as Administrator, then:
python main.py


