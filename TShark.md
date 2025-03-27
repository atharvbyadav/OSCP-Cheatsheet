# TShark

## 🦈 **Ultimate TShark Command Dictionary** 🦈

TShark is the command-line version of Wireshark and is powerful for **real-time packet analysis**, **capture filtering**, and **deep inspection**.

* * *

## 🔰 **1\. Basic Capture Commands**

| **Command** | **Description** |
| ---| --- |
| `tshark -D` | List all available network interfaces |
| `tshark -i eth0` | Capture packets on the `eth0` interface |
| `tshark -i wlan0 -c 100` | Capture **100 packets** from Wi-Fi interface |
| `tshark -i any` | Capture from **all** interfaces |
| `tshark -i eth0 -a duration:60` | Capture packets for **60 seconds** |

* * *

## 🎯 **2\. Packet Filtering (Display Filters)**

| **Command** | **Description** |
| ---| --- |
| `tshark -i eth0 -Y "ip.src == 192.168.1.1"` | Show packets from `192.168.1.1` |
| `tshark -i eth0 -Y "ip.dst == 8.8.8.8"` | Show packets going to Google DNS (`8.8.8.8`) |
| `tshark -i eth0 -Y "tcp.port == 80"` | Capture only **HTTP** (port 80) traffic |
| `tshark -i eth0 -Y "udp.port == 53"` | Capture only **DNS** (port 53) traffic |
| `tshark -i eth0 -Y "http.request.method == GET"` | Show only **HTTP GET requests** |

* * *

## 📂 **3\. Saving Captures to Files**

| **Command** | **Description** |
| ---| --- |
| `tshark -i eth0 -w capture.pcap` | Save packets to `capture.pcap` |
| `tshark -i eth0 -w capture.pcap -a duration:30` | Save packets for **30 seconds** |
| `tshark -i eth0 -w capture.pcap -b filesize:10000` | Save packets, split files every **10MB** |

* * *

## 📜 **4\. Reading & Analyzing Captures**

| **Command** | **Description** |
| ---| --- |
| `tshark -r capture.pcap` | Read a saved `pcap` file |
| `tshark -r capture.pcap -Y "http"` | Show only **HTTP traffic** from a `.pcap` file |
| `tshark -r capture.pcap -T fields -e ip.src -e ip.dst` | Extract source & destination IPs |

* * *

## 📊 **5\. Extracting Key Packet Information**

| **Command** | **Description** |
| ---| --- |
| `tshark -i eth0 -T fields -e ip.src -e ip.dst` | Display only **source and destination IPs** |
| `tshark -i eth0 -T fields -e frame.time -e ip.src -e ip.dst -e ip.proto` | Extract timestamp, source IP, destination IP, and protocol |
| `tshark -r capture.pcap -T json` | Convert `.pcap` to **JSON format** |
| `tshark -r capture.pcap -T fields -e` [`dns.qry.name`](http://dns.qry.name) | Extract only DNS queries |

* * *

## 🔍 **6\. Filtering Specific Protocols**

| **Command** | **Description** |
| ---| --- |
| `tshark -i eth0 -Y "dns"` | Capture **only DNS** packets |
| `tshark -i eth0 -Y "arp"` | Capture **only ARP** packets |
| `tshark -i eth0 -Y "icmp"` | Capture **only ICMP** (ping) packets |
| `tshark -i eth0 -Y "ssl"` | Capture **SSL/TLS** traffic |
| `tshark -i eth0 -Y "tcp.analysis.flags"` | Show **TCP retransmissions & errors** |

* * *

## 🔥 **7\. Extracting Credentials (HTTP, FTP, SMTP, etc.)**

| **Command** | **Description** |
| ---| --- |
| `tshark -i eth0 -Y "http.authbasic"` | Capture **Basic Auth credentials** |
| `tshark -i eth0 -Y "ftp.request.command == USER"` | Extract FTP usernames |
| `tshark -i eth0 -Y "ftp.request.command == PASS"` | Extract FTP passwords |
| `tshark -i eth0 -Y "smtp.req.parameter"` | Extract SMTP email logins |
| `tshark -i eth0 -Y "dhcp"` | Capture DHCP packets to see assigned IPs |

* * *

## 🕵️ **8\. Advanced Network Attack Detection**

| **Command** | **Description** |
| ---| --- |
| `tshark -i eth0 -Y "icmp.type == 8"` | Detect **ping sweeps** (ICMP Echo Requests) |
| `tshark -i eth0 -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0"` | Detect **port scans** (SYN packets) |
| `tshark -i eth0 -Y "udp.port == 1900"` | Detect **SSDP reflection attacks** |
| `tshark -i eth0 -Y "`[`dns.qry.name`](http://dns.qry.name) `== '`[`google.com`](http://google.com)`'"` | See who is querying [`google.com`](http://google.com) |
| `tshark -i eth0 -Y "ip.src == 192.168.1.100 and ip.dst == 192.168.1.1"` | Track specific **user activity** |

* * *

## ⚡ **9\. Extracting Files & Data from Packets**

| **Command** | **Description** |
| ---| --- |
| `tshark -r capture.pcap -Y "http contains image" -T fields -e http.file_data` | Extract **images** from HTTP packets |
| `tshark -r capture.pcap -Y "tcp.port == 21" -T fields -e ftp.retr.file` | Extract **files transferred via FTP** |
| `tshark -r capture.pcap -Y "http.response" -w extracted.pcap` | Extract **HTTP responses** |

* * *

## 🛠 **10\. Automation & Scripting**

| **Command** | **Description** |
| ---| --- |
| `tshark -i eth0 -T fields -e ip.src -e ip.dst > traffic.log` | Save IP logs to a file |
| `tshark -i eth0 -a duration:300 -w daily_capture.pcap` | Run a **5-minute** capture |
| \`tshark -r capture.pcap -T fields -e [http.host](http://http.host) | sort |
| \`tshark -i eth0 -Y "http" | tee http\_traffic.log\` |