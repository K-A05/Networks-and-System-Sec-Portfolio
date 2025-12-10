import hashlib
import os
import lief


#==== HASH-BASED SIGNATURE SCANNING ====#
"""
Attemtpts to identify known malware by comparing file hashes against a database of known malicious hashes.
Key Concepts
• Hash Functions: MD5, SHA1, SHA256 generate unique file fingerprints.
• Signature Database: A collection of known malicious file hashes.
• Detection: Matching a file's hash against the database indicates potential malware presence.
"""
# Example malware signatures (fake hashes for demonstration)
KNOWN_BAD_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",  # eicar test file (MD5)
    "5eb63bbbe01eeed093cb22bb8f5acdc3"   # fake malicious file hash
}

def md5_hash(path):
    """Compute MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): # for each chunk of 4KB in the file
            hash_md5.update(chunk) # hash that chunk
    return hash_md5.hexdigest() 

def scan_directory(directory): # enumerate the directory and scan for IOCs
    print(f"Scanning {directory}...\n")
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                file_hash = md5_hash(full_path)
                if file_hash in KNOWN_BAD_HASHES:
                    print(f"⚠️ MALWARE FOUND: {full_path}")
                else:
                    print(f"OK: {full_path}")
            except Exception as e:
                print(f"Error scanning {file}: {e}")

# Example usage
scan_directory("test_files")


#===== OPCODE-BASED SIGNATURE SCANNING =====#
"""
Attempts to identify malware by analysing the opcodes within an executable file, this is much harder for 
malware to evade since it inspects the machine code being executed on the CPU for known malicious patterns.
Key Concepts
• Disassembly: Converts binary code into human-readable assembly instructions.
• Opcode Patterns: Specific sequences of assembly code executed on the CPU level that are characteristic of a particular malware/family of malware.
• Detection: Matching opcode sequences against a database of known malicious patterns.
"""

from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# ------------------------------------------
# 1. Create the binary with simulated opcodes
# ------------------------------------------
asm = b"""
    nop
    nop
    nop
    xor eax, eax
    jmp $
"""

ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(asm)

with open("malicious_binary.bin", "wb") as f:
    f.write(bytes(encoding))

print("[+] Binary file 'malicious_binary.bin' created.")

# ------------------------------------------
# 2. Load + disassemble the binary
# ------------------------------------------
with open("malicious_binary.bin", "rb") as f:
    code = f.read()

disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

print("\nDisassembly:")
for i in disassembler.disasm(code, 0x1000):
    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

# ------------------------------------------
# 3. Extract opcodes
# ------------------------------------------
opcodes = [i.mnemonic for i in disassembler.disasm(code, 0)]

print("\nExtracted Opcodes:", opcodes)

# ------------------------------------------
# 4. Signature to match
# ------------------------------------------
SIGNATURE = ["nop", "nop", "nop", "xor", "jmp"]

# ------------------------------------------
# 5. Signature matching function
# ------------------------------------------
def match_signature(opcodes, signature):
    sig_len = len(signature)
    for i in range(len(opcodes) - sig_len + 1):
        if opcodes[i:i + sig_len] == signature:
            return True
    return False

# ------------------------------------------
# 6. Scan the binary
# ------------------------------------------
def scan_binary(file, signatures):
    with open(file, "rb") as f:
        code = f.read()

    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    opcodes = [i.mnemonic for i in disassembler.disasm(code, 0)]

    for sig in signatures:
        if match_signature(opcodes, sig):
            print(f"\n[MATCH] Malicious signature found: {sig}")
            return True

    print("\nNo signatures matched.")
    return False

# Run it
scan_binary("malicious_binary.bin", [SIGNATURE])