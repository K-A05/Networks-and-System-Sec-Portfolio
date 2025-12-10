
"""
To simulate how malware detection software identifies file tampering by
comparing current file hashes to a trusted baseline.
Key Concepts
• Change Detection: Compares new hashes against the baseline to
flag altered or deleted files.
• Heuristic Insight: Sudden modification of system or executable
files often indicates infection.
• Forensics Use: Detecting when and which files changed helps
trace intrusion paths.

💻 Write Python Code to Compare and Detect Changes

"""

import hashlib
import csv
import os

def hash_file(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def create_baseline(directory, baseline_file='baseline.csv'):
    with open(baseline_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['file', 'hash'])
        
        for f in os.listdir(directory):
            full = os.path.join(directory, f)
            if os.path.isfile(full):
                writer.writerow([f, hash_file(full)])
    print("Baseline created.")

def detect_changes(directory, baseline_file='baseline.csv'):
    # Load baseline
    baseline = {}
    with open(baseline_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            baseline[row['file']] = row['hash']

    # Compare
    for f in os.listdir(directory):
        full = os.path.join(directory, f)
        if os.path.isfile(full):
            new_hash = hash_file(full)
            if f not in baseline:
                print(f"[NEW] {f} was added")
            elif new_hash != baseline[f]:
                print(f"[MODIFIED] {f} was changed")
    
    # Check for deleted files
    for f in baseline:
        if not os.path.exists(os.path.join(directory, f)):
            print(f"[DELETED] {f} is missing")