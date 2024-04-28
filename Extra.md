# Extra

1. **FQDN of Domain Controller**

- [ ] nslookup <ip_address>

2. **Full Nmap Scan**

- [ ] nmap -sC -sV -A -T4 <ip_address>

3.  **Service Enumeration and Bruteforcing**

	1. FTP

- [ ] hydra -L <user_list> -P <password_list> (IP) ftp

	2. SNMP

- [ ] nmap -sP <ip_address> (Host Live Check)
- [ ] nmap -sU <ip_address> (UDP service)
- [ ] snmp-check <ip_address>
- [ ] [nmap snmp scripts and commands](https://nmap.org/search/?q=snmp)
- [ ] metasploit > msfconsole > search snmp > login

	3.  SMB

- [ ] nmap -p 445  --script smb-enum-shares <ip_address>
- [ ] hydra -L <user_list> -P <password_list> (IP) smb
- [ ] nmap --script smb-brute.nse -p445 <ip_address> (For port 445)
- [ ] sudo nmap -sU -sS --script smb-brute.nse -p U:137,T:139 <ip_address> (For Port 137 and 139)

> There are 2 Options to connect SMB :

- [ ] smbclient //<ip_address>/share_name -U <smb_username>

``OR

- [ ] sudo mount -t cifs //<ip_address>/share_name /mnt/smbshare -o username=<smb_username>,password=<smb_password> (Create /mnt/smbshare directory first)
- [ ] [nmap smb scripts and commands](https://nmap.org/search/?q=smb)

	4. RDP

- [ ] metasploit > msfconsole > rdp scanner
- [ ] hydra -L <user_list> -P <password_list> rdp://(IP) -s <rdp_port>
- [ ] xfreerdp /u:<rdp_username> /p:<rdp_password> /v:<rdp_ip>:<rdp_port>

	5. NetBIOS

- [ ] nmap -sV --script nbstat.nse <ip_address>


4. Highest Entropy in ELF files

- [ ] ent -c your_file.elf

5. ELF entry point

- [ ] readelf -h <file_name>
``OR``
- [ ] readelf --symbols <file_name>

6. IOT publish message in pcap file

- [ ] wireshark filter **mqtt.messageType == 3**
- [ ] Open packet > View Packet Details

7. Crack Wifi Password from Handshake

- [ ] aircrack-ng -a2 -b <bssid_network> -w <wordlist_provided> <handshake_file>

8. Vulnerability Analysis, End Of Life scan reports

- [ ] Openvas > login admin/password > scan > tasks > magic Wand icon for task wizard > enter IP > start scan