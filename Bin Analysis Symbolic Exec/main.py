import hashlib, pefile, re, yara

sample = "/procmon.exe"

def compute_hashes(path):
    algos = ["md5", "sha1", "sha256"]
    output = {}
    for a in algos:
        h = hashlib.new(a)
        with open(path, "rb") as f:
            h.update(f.read())
        output[a] = h.hexdigest()
    return output

def extract_strings(path):
    with open(path, "rb") as f:
        data = f.read()
    return re.findall(rb"[ -~]{4,}", data)

print("Hashes:", compute_hashes(sample))

print("\nStrings:")
print(extract_strings(sample)[:10])

print("\nImports:")
pe = pefile.PE(sample)
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(entry.dll.decode())

print("\nIOCs:")
decoded = open(sample, "rb").read().decode(errors="ignore")
print("URLs:", re.findall(r"https?://[^\s\"']+", decoded))
print("IPs:", re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", decoded))

print("\nYARA:")
rule = yara.compile(source="""
rule Simple {
strings: $s = "http"
condition: $s
}
""")

print(rule.match(sample))