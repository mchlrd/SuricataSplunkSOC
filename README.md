# Home SOC Lab with Suricata IDS and Splunk Visualization

## Overview

This repository demonstrates a **self-contained Security Operations Center (SOC) home lab** designed to simulate real-world network security monitoring. The lab integrates:

- **Kali Linux** as an attacker system  
- **Windows 10/11** as a target/victim system  
- **Suricata IDS** for network intrusion detection  
- **Splunk Enterprise** for real-time alert visualization and dashboarding  

The project focuses on **network traffic inspection, intrusion detection, log analysis, and visualization** in a controlled virtualized environment.

---

## Technical Features

### Suricata IDS Integration
- Stateful inspection of network packets  
- Detection of reconnaissance techniques, including:  
  - ICMP pings  
  - TCP SYN scans  
  - Nmap full scans  
  - Null and FIN scans  
  - Custom local detection rules  
- Real-time logging to `fast.log` and optional `eve.json` for structured events  

### Splunk Enterprise Monitoring
- Directory monitor input for Suricata log ingestion  
- Custom `sourcetype` for Suricata logs  
- Time-series visualization (timeline charts) for event correlation  
- Pie charts for alert type distribution and top attacker IPs  
- Real-time dashboards simulating SOC workflows  

### Network Virtualization
- Virtualized lab environment using VMware Workstation/Player  
- NAT and host-only network adapters for traffic isolation  
- Multiple subnets for attacker/victim segmentation (e.g., 192.168.78.0/24)  
- Controlled IP addressing for deterministic alert generation  

---

## Lab Architecture

```text
[Kali Linux VM] -- Attacker
      |
      | generates ICMP, TCP SYN, and Nmap traffic
      v
[Windows 10 VM] -- Victim
      |
      | monitored by
      v
[Suricata IDS] -- Logs alerts to /var/log/suricata/fast.log
      |
      | indexed by
      v
[Splunk Enterprise] -- Dashboards & visualization
```
## 🛠 Installation Requirements

### Hardware
| Component | Requirement |
| :--- | :--- |
| **RAM** | 32 GB (Lab tested) |
| **CPU** | Multi-core (4+ cores recommended) |
| **Storage** | 50 GB free disk space |

### Software
* **Hypervisor:** VMware Workstation / Player
* **OS:** Kali Linux (Latest stable), Windows 10/11 VM
* **IDS:** Suricata IDS (v7.x+)
* **SIEM:** Splunk Enterprise (v9.x+)
* **Dependencies:** `libpcap`, `pcre`, `nss`, `yaml-cpp`, Java Runtime (bundled)

---

## ⚙️ Setup & Configuration

### 1. Virtual Network Setup
Configure VMware NAT and Host-Only adapters to ensure the Kali IDS and Windows Target can communicate on a private subnet.

* **Subnet:** `192.168.78.0/24`
* **Kali IP:** `192.168.78.10`
* **Windows IP:** `192.168.78.11`

### 2. Suricata IDS Configuration
Install Suricata on the Kali VM:

```bash
sudo apt update && sudo apt install suricata -y
```
## 🔍 Custom Detection Rules
Define detection logic in `/etc/suricata/rules/local.rules`:

```suricata
alert icmp any any -> any any (msg:"ICMP ping detected"; sid:1000001; rev:1;)
alert tcp any any -> any any (flags:S; msg:"TCP SYN scan detected"; sid:1000002; rev:1;)
alert tcp any any -> any any (msg:"Nmap scan detected"; flow:to_server,established; sid:1000003; rev:1;)
alert tcp any any -> any any (msg:"Port scan detected"; threshold:type both, track by_src, count 10, seconds 60; sid:1000004; rev:1;)
alert tcp any any -> any any (flags:0; msg:"Null scan detected"; sid:1000005; rev:1;)
alert tcp any any -> any any (flags:F; msg:"FIN scan detected"; sid:1000006; rev:1;)
```
## 🚀 Service Activation

1.  **Include local rules** in `suricata.yaml`:
    ```yaml
    rule-files:
      - local.rules
    ```

2.  **Start the engine** on the primary interface:
    ```bash
    sudo suricata -c /etc/suricata/suricata.yaml -i eth0
    ```

3.  **Monitor the alert log** in real-time:
    ```bash
    tail -f /var/log/suricata/fast.log
    ```

---

## 🛡️ Splunk Enterprise Configuration
Install Splunk and configure it to ingest Suricata logs for visualization.

```bash
sudo tar -xvzf splunk-<version>-linux-x86_64.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license
```
## 📊 SOC Dashboard Creation (SPL)
Use the following queries within Splunk to build real-time monitoring panels for your SOC dashboard.

### Alert Timeline
Visualizes the frequency of different alert types over time.
```splunk
index=main sourcetype=suricata source="/var/log/suricata/fast.log"
| timechart count by msg
```
### Alert Distribution (Pie Chart)
Provides a breakdown of the most common signature matches
```splunk
index=main sourcetype=suricata source="/var/log/suricata/fast.log"
| stats count by msg
```
### Top Attacking IPs
Identifies the most active source addresses in the network.

```splunk
index=main sourcetype=suricata source="/var/log/suricata/fast.log"
| stats count by src_ip
| sort -count
```
## 🧪 Testing & Validation

To verify the integration, generate various types of traffic from the **Kali VM (Attacker)** to the **Windows VM (Target)**.



### Execution Commands

# 1. ICMP Connectivity Testing

```bash
ping 192.168.78.11
```
# 2. Nmap Scanning Techniques
```bash
nmap -sS 192.168.78.11  # Stealth SYN Scan
nmap -sN 192.168.78.11  # Null Scan
nmap -sF 192.168.78.11  # FIN Scan
nmap -A 192.168.78.11   # Aggressive Scan (OS & Version Detection)
```
