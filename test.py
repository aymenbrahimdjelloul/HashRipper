# Author : Aymen Brahim Djelloul
# This file is test of HashRipper
import hashripper
import hashlib
from time import perf_counter
import re

# Get a hexdigest of 'test' word using MD5 function
_word: bytes = b"test"
_hash: bytes = hashlib.md5(_word).hexdigest()

# Create HashRipper object uisng CLI mode
r = hashripper.HashRipper(cli_mode=True)

# crack it
print(f" MD5 hash of word '{str(_word)}' : {_hash}")
print(r.crack(_hash))

# OUTPUT : 
#  MD5 hash of word 'test' : 098f6bcd4621d373cade4e832627b4f6
# [*] - HashRipper - V 1.1 initialized with 1.65M words
# [*] - Detected hash method: md5 .
# {'password': 'test', 'hash_method': 'md5', 'time_taken': 4.3865, 'successful': True, 'error': None}
