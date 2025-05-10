import hashripper
import hashlib
from time import perf_counter
import re


_word: bytes = b"test"
_hash: bytes = hashlib.md5(_word).hexdigest()

r = hashripper.HashRipper(cli_mode=True)

print(f" MD5 hash of word '{str(_word)}' : {_hash}")
print(r.crack(_hash))
