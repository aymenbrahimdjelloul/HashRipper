
"""
@author : Aymen Brahim Djelloul
version : 1.0
date : 02.09.2023
LICENSE : MIT


          _    _           _       _____  _
         | |  | |         | |     |  __ \(_)
         | |__| | __ _ ___| |__   | |__) |_ _ __  _ __   ___ _ __
         |  __  |/ _` / __| '_ \  |  _  /| | '_ \| '_ \ / _ \ '__|
         | |  | | (_| \__ \ | | | | | \ \| | |_) | |_) |  __/ |
         |_|  |_|\__,_|___/_| |_| |_|  \_\_| .__/| .__/ \___|_|
                                           | |   | |
                                           |_|   |_|


    // HashRipper is a simple and light-weight tool to crack a hash using wordlist


"""

# IMPORTS
import sys
import os.path
import shutil
from time import perf_counter, sleep
from exceptions import *
from const import *


class HashRipper:

    # DEFINE EMPTY VARIABLE FOR ATTEMPTS PER SECOND
    _ATTEMPTS_PER_SECOND: int = 0

    def __init__(self, _hash: str, wordlist: str, interface_mode: bool = False):

        # Get the hash function
        self.hashing_func = self.__get_hashing_function(_hash)
        self._hash = _hash
        self.interface_mode = interface_mode

        # Define empty list for wordlist
        self._wordlist: list = []

        if self.__is_valid_wordlist(wordlist):
            # Load wordlist content
            self.__load_wordlist_pass(wordlist)
            # get the passwords wordlist hashed
            self.__hashed_wordlist: list = self.__hash_wordlist()
            # print(self.hashed_wordlist)

        else:
            raise WordlistNotFound

    def crack(self):
        """ This method will crack the given hash by performing a wordlist attack"""

        # Define empty password variable
        word: str = ""

        # Get the start cracking time
        s_time: float = perf_counter()
        # Iterate through the given wordlist
        for _hash in self.__hashed_wordlist:
            # Compare the two hashes
            if self._hash == _hash:
                # Get the word compatible with the found hash
                word = self._wordlist[self.__hashed_wordlist.index(_hash)]

                # Check if the program is running on interface mode
                if self.interface_mode:
                    # Clear console
                    os.system(CONSOLE_CLEAR)
                    # Print out the result
                    print(f"\nPassword : {word}{' ' * 50}Cracked in : {self.__friendly_time_format(perf_counter() - s_time)}\n")

                    # Clear memory
                    del self.__hashed_wordlist, s_time, _hash, self._hash

                    return

                else:
                    # Clear memory
                    del self.__hashed_wordlist, s_time, _hash, self._hash

                    # return the password only when it's not runs on interface
                    return word

        # return None when password not found
        # Check if the for loop terminated

        if self.interface_mode:
            # Clear console
            os.system(CONSOLE_CLEAR)
            # Print out the result
            print(f"\n\nPassword not found ! Please try another wordlist .\n\n")

            # Clear memory
            del self.__hashed_wordlist, word, s_time, _hash, self._hash

        else:
            # Clear memory
            del self._wordlist, self.__hashed_wordlist, word, s_time, _hash, self._hash

            return None

    def __get_hashing_function(self, _hash: bytes) -> str:
        """ This method will return the hashing function name of the used hash"""

        # Get the hash length
        hash_length: int = len(_hash)
        for length in HASHES_LENGTH.keys():

            # Compare the hash lengths
            if length == hash_length:
                # Clear memory
                del hash_length, _hash
                return HASHES_LENGTH[length]

        # Clear memory
        del hash_length, _hash, length
        # Raise A Hash function cannot be detected
        raise HashFunctionCannotBeDetected

    def __get_pass_hash(self, password: bytes) -> bytes:
        """ This method will return a password hash using the determined hashing function"""
        return HASH_FUNCTIONS[self.hashing_func](password.encode("UTF-8")).hexdigest()

    @staticmethod
    def __is_valid_wordlist(file_path: str) -> bool:
        """ This method will check if the wordlist file is valid"""
        return True if os.path.exists(f"{os.getcwd()}\\{file_path}") else False

    def __load_wordlist_pass(self, file_path: str):
        """ This method will load the wordlist"""

        # Read passwords from wordlist
        try:
            with open(f"{os.getcwd()}\\{file_path}", "r", encoding="UTF-8") as file:
                self._wordlist = file.read().split()

            # Clear memory
            del file_path, file

        # Handle exceptions
        except UnicodeDecodeError:
            raise WordlistCannotBeUsed

        except PermissionError:
            raise WordlistCannotBeUsed

    def get_remaining_time(self) -> str | float:
        """ This method will calculate the estimation of the time remaining for hash crack"""

        # Get the time taken of a single iter
        # Store the start time
        s_time: float = perf_counter()

        # make one iterate
        for i in self._wordlist:
            password_hash: str = self.__get_pass_hash(i)

            if self._hash == password_hash:
                pass

            break

        # Store the end time
        end_time: float = perf_counter()

        # Calculate remaining time in seconds
        remaining_time: flaot = (end_time - s_time) * len(self._wordlist)

        # Calculate the attempts per seconds
        self.__ATTEMPTS_PER_SECOND = 1 / (end_time - s_time)

        # Clear memory
        del s_time, i, password_hash, end_time
        # Get the friendly remaining time and return it
        return self.__friendly_time_format(remaining_time) if self.interface_mode else remaining_time

    def __hash_wordlist(self) -> list:
        """ This method will return a list contain hashes of given wordlist"""

        # Define empty list for hashes wordlist
        hashed_wordlist: list = []

        # Define the word hashing function
        hash_function: str = HASH_FUNCTIONS[self.__get_hashing_function(self._hash)]

        for word in self._wordlist:

            # Get the word hash
            hashed_wordlist.append(hash_function(word.encode("UTF-8")).hexdigest())

        # Clear memory
        del word
        # Return the hashes wordlist
        return hashed_wordlist

    @staticmethod
    def __friendly_time_format(seconds: float) -> str:
        """ This method will convert the seconds into friendly time format"""

        # Convert seconds parameter into int
        _seconds = int(seconds)

        # Calculate the hours, minutes, and seconds
        hours = _seconds // 3600
        minutes = (_seconds % 3600) // 60
        seconds = _seconds % 60
        milliseconds = (_seconds % 1) * 1000

        # Format the time string
        # handle hours and minutes
        time_str = ""
        if hours > 0:
            time_str += f"{hours} hours"
        if minutes > 0 or hours > 0:
            time_str += f" {minutes} minutes"

        # handle seconds
        if _seconds <= 60:
            time_str = f"{seconds} seconds"

        # handle milliseconds
        if seconds == 0:
            time_str += f"{int(milliseconds)} milliseconds"

        # Clear memory
        del _seconds, seconds, hours, minutes, milliseconds
        return time_str


def __center_text(text: str) -> str:
    """ This function will get the text and center it to the terminal screen"""
    return F"{" " * ((WIDTH - len(text)) // 2)}{text}"


def main():
    """ This function is the main to start Hash Ripper"""

    # Set window title
    if platform == "win32":
        os.system(f"title HashRipper - {VERSION}")

    print(__center_text(f"\n{BANNER}\n"))
    _hash = str(input(f"   Enter the HASH : "))
    wordlist_path = str(input(f"   Wordlist Path : "))

    # Create HashCrack object
    try:
        hash_crack_obj = HashRipper(_hash, wordlist_path, interface_mode=True)

        # Print the detected hash function with the number of passwords to try
        # With the question if the user is ready!
        print(__center_text(f"\nHash Function used : {hash_crack_obj.hashing_func}")
              + __center_text(f"Count Passwords : {len(hash_crack_obj._wordlist)}"))

        # Print the estimated remaining time
        print(f"Remaining time : {hash_crack_obj.get_remaining_time()}"
              f"{' ' * 30}Attempts per second : {int(hash_crack_obj._ATTEMPTS_PER_SECOND)}")

        # Clear memory
        del _hash, wordlist_path

        # Ask the user
        answer = str(input("\nAre you ready to start ? [Y|N]")).lower()
        if answer.upper() == "Y":
            # Start the Cracking
            hash_crack_obj.crack()
            input("Press Enter to retry..\n\n\n")
            # Restart the main function
            os.system(CONSOLE_CLEAR)
            main()

        elif answer.upper() == "N":
            # otherwise clear the console and rerun the software
            os.system(_CONSOLE_CLEAR)
            main()

    # Errors Handling
    except WordlistNotFound:
        print(f"Cannot get the wordlist. Please press Enter to try Again!")
        input()
        # Clear console
        os.system(_CONSOLE_CLEAR)
        main()
        return


if __name__ == "__main__":
    # LAUNCH THE APP
    main()
