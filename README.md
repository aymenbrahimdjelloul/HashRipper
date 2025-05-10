<div align="left">
  <img src="https://github.com/aymenbrahimdjelloul/HashRipper/blob/main/images/icon.png" alt="HashRipper Logo" width="150" height="150">
</div>

<a href="https://github.com/aymenbrahimdjelloul/HashRipper/releases/latest">
    <img src="https://img.shields.io/github/v/release/aymenbrahimdjelloul/HashRipper?color=green&label=Download&style=for-the-badge" alt="Download Latest Release">
  </a>

# **HashRipper**
#### A Pure-Python Hash Cracking Tool

**HashRipper** is a lightweight, efficient tool designed for cracking cryptographic hashes using both wordlist and brute-force attacks. It aims to be fast, flexible, and user-friendly, supporting multiple hash types and performance enhancements like multiprocessing and GPU acceleration.

---

## **Key Features**

- ✅ Supports **Wordlist** and **Brute-force** attacks  
- ✅ Automatically detects hash types: `MD5`, `SHA1`, `SHA128`, `SHA256`  
- ✅ Fetches wordlists from multiple **online sources**  
- ✅ Utilizes **multiprocessing** for faster execution  
- ✅ Supports **GPU acceleration** to boost brute-force attacks

---

## Simple Usage Example:

~~~python
import hashripper
import hashlib

# Get a hexdigest of 'test' word using MD5 function
_word: bytes = b"test"
_hash: bytes = hashlib.md5(_word).hexdigest()

# Create HashRipper object uisng CLI mode
r = hashripper.HashRipper(cli_mode=True)

# crack it
print(f" MD5 hash of word '{str(_word)}' : {_hash}")
print(r.crack(_hash))
~~~
#### Output :
~~~

MD5 hash of word 'test' : 098f6bcd4621d373cade4e832627b4f6

[*] - HashRipper - V 1.1 initialized with 1.65M words

[*] - Detected hash method: md5 .

{'password': 'test', 'hash_method': 'md5', 'time_taken': 4.3865, 'successful': True, 'error': None}

~~~


---

## **How It Works**

HashRipper operates in two main modes:

1. **Wordlist Attack:**  
   The tool compares the hash against entries from one or more wordlists. These wordlists can be local or fetched from remote sources.

2. **Brute-Force Attack:**  
   HashRipper tries all possible combinations of characters (based on configurable rules) to find the original plaintext value of the hash. This method can be accelerated using GPU hardware.

HashRipper attempts to automatically detect the hash type based on its length and pattern, removing the need for manual selection.

---

## **Why HashRipper?**

- **Pure Python:** No dependencies on complex C/C++ libraries—easy to run anywhere.  
- **Performance:** Efficient use of threads and processes to scale across CPU cores and leverage GPUs.  
- **Flexibility:** Customizable settings for hash types, attack methods, charset, length, and more.  
- **Community-Driven:** Built to be open, extensible, and responsive to user feedback.

---

## **Contribute**

We welcome contributions to **HashRipper**! Whether you're fixing a bug, suggesting a feature, or submitting code, your help makes this tool better.

**To contribute:**
1. Fork the repository.
2. Create a new branch (`feature/my-feature` or `fix/my-bug`).
3. Make your changes and test thoroughly.
4. Submit a pull request with a detailed description.

---

## **Thanks**

Special thanks to:

- **Cybersecurity Experts** – for providing best practices and guidance.
- **Open Source Contributors** – for generously sharing your time and skills.
  
Thank you for using **HashRipper** – Stay safe and crack responsibly!
---
### License : 
~~~
MIT License

Copyright (c) 2023 Aymen Brahim Djelloul

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

~~~
