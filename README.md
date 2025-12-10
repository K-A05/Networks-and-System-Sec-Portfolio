# Networks and System Security Portfolio
- A collection of some of the activities and exercises undertaken during the labs exploring concepts of brute force and dictionary attacks, cryptography and hashing, malicious software, forensic techniques such as file sniffing, malicious signature scans, network scanning, enumeration and simulated propogation across a network.

# Personal efforts and contributions:
- I have used some of these lab exercises as opportunities for exploration of advanced concepts, such as opcode based malware analysis, that checks for patterns of machine code that are characteristic of malware/variants of a malware.
- Creating a "worm": creating a worm class with functions of scanning hosts on the network using the arp protocol, performing an ICMP flush to show how such a worm would check for open ports and services + add functionality to measure the RTT timing / host found on the network + OUI identification through mac address parsing (parsing the first 8 bytes of the returned MAC and comparing it against the IEEE OUI database[https://standards-oui.ieee.org/oui/oui.txt]).

# Organisation
- The contents of this directory are organised as follows:
Networks and System Security
|__ Password-analysis
|_____password_meter.py (script to test and rate the strenght and entropy of a password)
|_____salt and pepper.py (demonstrate salting and peppering in hashes)
|_____brute.py (simulation of a bruteforce attack using a dictionary)
|_____auth.py (full integration final solution with 2FA authentication, password checks etc.)
|__crypto
|_____key_gen.py
|_____sender.py
|_____receiver.py
|__malicious software
|_____file_sniffer.py
|_____SHA_hash.py
|_____signature_scan.py
|_____worm.py
|__Bin Analysis and Symbolic Exec
|_____main.py (main script)
|___Pentesting
|_____nmap.py
|___GenAI
|_____ollama.py

# Configuration and management
- For the management of project dependencies and virtual environments, I made use of uv (https://github.com/astral-sh/uv) along, included in this directory is the pyproject.toml, which contains all the dependencies needed for the scripts within this portfolio.