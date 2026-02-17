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
