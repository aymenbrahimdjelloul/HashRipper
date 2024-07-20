"""
@author : Aymen Brahim Djelloul
version : 1.0
date : 02.09.2023
LICENSE : MIT

"""

# IMPORTS
import sys


class WordlistNotFound(BaseException):

    def __str__(self):
        return "The wordlist file you haved been use Can not be found!"


class WordlistCannotBeUsed(BaseException):

    def __str__(self):
        return "The wordlist content might be corrupted or incorrect"


class HashFunctionCannotBeDetected(BaseException):

    def __str__(self):
        return "The hash function used in your hash cannot be detected by HashCrack!\n" \
               "Please use a supported hash function"

if __name__ == "__main__":
    sys.exit()
