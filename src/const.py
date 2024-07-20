"""
@author : Aymen Brahim Djelloul
version : 1.0.0
date : 19.07.2024
License : MIT

"""

# IMPORTS
import hashlib
import shutil
import sys

# DEFINE VARIABLES
AUTHOR: str = "Aymen Brahim Djelloul"
VERSION: str = "1.0"
SUPPORTED_HASH_FUNCTIONS: tuple = ("md5", "sha1", "sha3", "sha256",
                            "sha224", "sha384", "sha512")

WIDTH = shutil.get_terminal_size()[0]

# Define colors variables
# BOLD_FONT: str = "\033[1m"
# RED__ = "\033[31m"
# GREEN__ = "\033[32m"
# YELLOW = "\033[93m"
# BLUE = "\033[34m"
# PURPLE = "\033[95m"
# COLOR_RESET = "\033[0m"


BANNER: str = f"""

      _    _           _       _____  _                       
     | |  | |         | |     |  __ \(_)                      
     | |__| | __ _ ___| |__   | |__) |_ _ __  _ __   ___ _ __ 
     |  __  |/ _` / __| '_ \  |  _  /| | '_ \| '_ \ / _ \ '__|
     | |  | | (_| \__ \ | | | | | \ \| | |_) | |_) |  __/ |   
     |_|  |_|\__,_|___/_| |_| |_|  \_\_| .__/| .__/ \___|_|   
                                       | |   | |              
                                       |_|   |_|              
                                                     
        =================================================
          AUTHOR : {AUTHOR}
          VERSION : {VERSION}
          Protected Under MIT License Copyright 2023
        ================================================ """


# DECLARE SOME VARIABLES
HASHES_LENGTH: dict = {
    32: "md5",      # md5    : 128bit
    40: "sha1",     # sha1   : 160bit
    56: "sha224",   # sha224 : 224bit
    64: "sha256",   # sha256 : 256bit
    96: "sha384",   # sha384 : 384bit
    128: "sha512"    # sha512 : 512bit
}

# DEFINE HASH FUNCTIONS ON DICTIONARY
HASH_FUNCTIONS: dict = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512
}

platform: str = sys.platform
CONSOLE_CLEAR: str = "cls" if platform == "win32" else "clear"


if __name__ == "__main__":
    sys.exit()
