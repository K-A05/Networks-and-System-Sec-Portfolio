# Networks and System Security Portfolio
- A collection of some of the activities and exercises undertaken during the labs exploring concepts of brute force and dictionary attacks, cryptography and hashing, malicious software, forensic techniques such as file sniffing, malicious signature scans, network scanning, enumeration and simulated propogation across a network.

# Personal efforts and contributions:
- I have used some of these lab exercises as opportunities for exploration of advanced concepts, such as opcode based malware analysis, that checks for patterns of machine code that are characteristic of malware/variants of a malware.
- Creating a "worm": creating a worm class with functions of scanning hosts on the network using the arp protocol, performing an ICMP flush to show how such a worm would check for open ports and services + add functionality to measure the RTT timing / host found on the network + OUI identification through mac address parsing (parsing the first 8 bytes of the returned MAC and comparing it against the IEEE OUI database[https://standards-oui.ieee.org/oui/oui.txt]).

<img width="781" height="478" alt="Screenshot 2025-12-10 at 12 35 58 PM" src="https://github.com/user-attachments/assets/25c5c064-7e42-47b6-8f83-395cf87e2bfa" />


# Configuration and management
- For the management of project dependencies and virtual environments, I made use of uv (https://github.com/astral-sh/uv) along, included in this directory is the pyproject.toml, which contains all the dependencies needed for the scripts within this portfolio.
