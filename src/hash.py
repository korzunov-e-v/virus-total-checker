import sys
import hashlib

BUF_SIZE = 65536
sha256 = hashlib.sha256()

with open(sys.argv[1],'rb') as f:
    while True:
        data = f.read(BUF_SIZE)
        if not data:
            break
        sha256.update(data)

print(sha256.hexdigest())
input()