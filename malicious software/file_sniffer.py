import csv
import hashlib
import os

def file_sniffer(file):
    """Takes an input file/directory and loops through each item, 
    generating a SHA256 hash for each line, 
    and storing the results in a CSV file, 
    with the file name and its corresponding hash."""
    output_file = "file_hashes.csv"
    
    with open(output_file, mode='w', newline='') as csvfile:
        fieldnames = ['file_name', 'line_hash']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        if os.path.isfile(file): # switch case between file and directory
            files_to_process = [file]
        elif os.path.isdir(file):
            files_to_process = [os.path.join(file, f) for f in os.listdir(file) if os.path.isfile(os.path.join(file, f))]
        else:
            raise ValueError("The provided path is neither a file nor a directory.")
        
        for filepath in files_to_process:
            with open(filepath, 'rb') as f:
                file_bytes = f.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                writer.writerow({'file_name': os.path.basename(filepath), 'line_hash': file_hash})
    print(f"Hashes written to {output_file}")

# Example usage:
target = os.path.join(os.path.dirname(__file__), 'cats')

file_sniffer(target)    
