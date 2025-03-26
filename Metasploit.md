# Metasploit Framework

The Metasploit Framework is a set of tools that allow information gathering, scanning, exploitation, exploit development, post-exploitation, and more. While the primary usage of the Metasploit Framework focuses on the penetration testing domain, it is also useful for vulnerability research and exploit development.

  

The main components of the Metasploit Framework can be summarized as follows;

*   **msfconsole**: The main command-line interface.
*   **Modules**: supporting modules such as exploits, scanners, payloads, etc.
*   **Tools**: Stand-alone tools that will help vulnerability research, vulnerability assessment, or penetration testing. Some of these tools are msfvenom, pattern\_create and pattern\_offset. We will cover msfvenom within this module, but pattern\_create and pattern\_offset are tools useful in exploit development which is beyond the scope of this module.

  

*   **Exploit**: A piece of code that uses a vulnerability present on the target system.
*   **Vulnerability**: A design, coding, or logic flaw affecting the target system. The exploitation of a vulnerability can result in disclosing confidential information or allowing the attacker to execute code on the target system.
*   **Payload**: An exploit will take advantage of a vulnerability. However, if we want the exploit to have the result we want (gaining access to the target system, read confidential information, etc.), we need to use a payload. Payloads are the code that will run on the target system.

## Payloads

Payloads are codes that will run on the target system.

```elixir
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 payloads/
```

### **Payloads Subdirectories:**

*   **adapters**
*   **singles**
*   **stagers**
*   **stages**

### **Four different directories under payloads: adapters, singles, stagers and stages.**

*   **Adapters**: An adapter wraps single payloads to convert them into different formats. For example, a normal single payload can be wrapped inside a Powershell adapter, which will make a single powershell command that will execute the payload.
*   **Singles**: Self-contained payloads (add user, launch notepad.exe, etc.) that do not need to download an additional component to run.
*   **Stagers**: Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. “Staged payloads” will first upload a stager on the target system then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
*   **Stages**: Downloaded by the stager. This will allow you to use larger sized payloads.

  

**Metasploit has a subtle way to help you identify single (also called “inline”) payloads and staged payloads.**

*   generic/shell\_reverse\_tcp
*   windows/x64/shell/reverse\_tcp

## Post

Post modules will be useful on the final stage of the penetration testing process listed above, post-exploitation.

```bash
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 post/
```

### **Post-Exploitation Subdirectories:**

*   **aix**
*   **android**
*   **apple\_ios**
*   **bsd**
*   **firefox**
*   **hardware**
*   **linux**
*   **multi**
*   **networking**
*   **osx**
*   **solaris**
*   **windows**

## Auxiliary

Any supporting module, such as scanners, crawlers and fuzzers, can be found here.

```bash
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 auxiliary/
```

### Subdirectories:

*   **admin**
*   **analyze**
*   **bnat**
*   **client**
*   **cloud**
*   **crawler**
*   **docx**
*   **dos**
*   **fileformat**
*   **fuzzers**
*   **gather**
*   **parser**
*   **pdf**
*   **scanner**
*   **server**
*   **sniffer**
*   **spoof**
*   **sqli**
*   **voip**
*   **vsploit**

Additionally, the module contains two example scripts:

*   [**example.py**](http://example.py)
*   **example.rb**

## Encoders

Encoders will allow you to encode the exploit and payload in the hope that a signature-based antivirus solution may miss them.

```bash
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 encoders/
```

### **Encoders Subdirectories:**

*   **cmd**
*   **generic**
*   **mipsbe**
*   **mipsle**
*   **php**
*   **ppc**
*   **ruby**
*   **sparc**
*   **x64**
*   **x86**

## Evasion

While encoders will encode the payload, they should not be considered a direct attempt to evade antivirus software. On the other hand, “evasion” modules will try that, with more or less success.

```bash
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 2 evasion/
```

### **Evasion Module Structure:**

*   **windows/**
    *   **applocker\_evasion\_install\_util.rb**
    *   **applocker\_evasion\_msbuild.rb**
    *   **applocker\_evasion\_presentationhost.rb**
    *   **applocker\_evasion\_regasm\_regsvcs.rb**
    *   **applocker\_evasion\_workflow\_compiler.rb**
    *   **process\_herpaderping.rb**
    *   **syscall\_inject.rb**
    *   **windows\_defender\_exe.rb**
    *   **windows\_defender\_js\_hta.rb**

## Exploits

Exploits, neatly organized by target system.

```bash
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 exploits/
```

### **Exploits Subdirectories:**

*   **aix**
*   **android**
*   **apple\_ios**
*   **bsd**
*   **bsdi**
*   **dialup**
*   **firefox**
*   **freebsd**
*   **hpux**
*   **irix**
*   **linux**
*   **mainframe**
*   **multi**
*   **netware**
*   **openbsd**
*   **osx**
*   **qnx**
*   **solaris**
*   **unix**
*   **windows**

Additionally, the directory contains example exploit files:

*   **example\_linux\_priv\_esc.rb**
*   [**example.py**](http://example.py)
*   **example.rb**
*   **example\_webapp.rb**

## NOPs

NOPs (No OPeration) do nothing, literally. They are represented in the Intel x86 CPU family with 0x90, following which the CPU will do nothing for one cycle. They are often used as a buffer to achieve consistent payload sizes.

```bash
root@ip-10-10-135-188:/opt/metasploit-framework/embedded/framework/modules# tree -L 1 nops/
```

### **NOPs Subdirectories:**

*   **aarch64**
*   **armle**
*   **cmd**
*   **mipsbe**
*   **php**
*   **ppc**
*   **sparc**
*   **tty**
*   **x64**
*   **x86**

  

# `msfconsole` :

  

```bash
root@ip-10-10-220-191:~# msfconsole 

msf6 > ls
[*] exec: ls
burpsuite_community_linux_v2021_8_1.sh	Instructions  Scripts
Desktop					Pictures      thinclient_drives
Downloads				Postman       Tools

msf6 > ping -c 1 8.8.8.8
[*] exec: ping -c 1 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=109 time=1.33 ms
--- 8.8.8.8 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.335/1.335/1.335/0.000 ms

msf6 > help set
Usage: set [option] [value]

msf6 > history

msf6 >
```