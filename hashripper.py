"""
@author : Aymen Brahim Djelloul
version : 1.1
date : 07.05.2025
license : MIT


"""
# IMPORTS
import sys
import os
import json
import copy
import hashlib
import socket
import colorama
import requests
import datetime
import traceback
import contextlib
from time import perf_counter, sleep
from itertools import product
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Set, Tuple, List, Union, Optional, Callable, Generator, Any
from functools import lru_cache

# Import CLI dependencies
import colorama, shutil
from colorama import Fore, Style
from tqdm import tqdm

try:
    import torch
    HAS_TORCH = True

except ImportError:
    HAS_TORCH = False


class _Const:

    AUTHOR: str = "Aymen Brahim Djelloul"
    VERSION: str = "1.1"
    DATE: str = "10.05.2025"

    SUPPORTED_HASH_FUNCTIONS: tuple = ("md5", "sha1", "sha3", "sha256",
                                       "sha224", "sha384", "sha512")

    CACHE_PATH: str = ".cache"
    CACHE_FILENAME: str = "wordlist_cache.json"

    # DECLARE SOME VARIABLES
    HASHES_LENGTH: dict = {
        32: "md5",  # md5    : 128bit
        40: "sha1",  # sha1   : 160bit
        56: "sha224",  # sha224 : 224bit
        64: "sha256",  # sha256 : 256bit
        96: "sha384",  # sha384 : 384bit
        128: "sha512"  # sha512 : 512bit
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

    # Define wordlists urls
    WORDLISTS: tuple = (
        "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/refs/heads/master/Real-Passwords/Top304Thousand-probable-v2.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Keyboard-Walks/Keyboard-Combinations.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Keyboard-Walks/walk-the-line.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/000webhost.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/NordVPN.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/Ashley-Madison.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/youporn2012-raw.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/seasons.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Leaked-Databases/tuscl.txt"

    )


# class _CacheHandler(_Const):
#     """Handles caching of wordlists and cracked hashes."""
#
#     def __init__(self) -> None:
#         super().__init__()
#
#         # Ensure cache directory exists
#         os.makedirs(self.CACHE_PATH, exist_ok=True)
#
#     def collect_wordlist(self) -> Set[str] | None:
#         """Load the cached wordlist."""
#
#         wordlist: set = set()
#         cache_filename: str = f"{self.CACHE_PATH}{self.CACHE_FILENAME}"
#
#         # Check if cache file exists
#         if not os.path.exists(cache_filename):
#             return None
#
#         try:
#
#             with open(cache_filename, "rb") as f:
#                 data = json.loads(f.read())
#
#         except Exception:
#             return None
#
#         return wordlist
#
#     def save_cache(self, wordlist: set) -> None:
#         """ This method will save the given wordlist into cache"""
#
#     @staticmethod
#     def _get_data_checksum(data: bytes) -> str:
#         """ This method will get the data and return the MD5 checksum hash"""
#         return hashlib.md5(data).hexdigest()


# class _GPUAccelerator:
#     """Handles GPU acceleration for hash cracking when available."""
#
#     def __init__(self) -> None:
#         self.available = HAS_TORCH
#
#
class _WordlistHandler:

    HEADERS: dict = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/91.0.4472.124 Safari/537.36"

    }

    TIMEOUT: int = 5

    def __init__(self) -> None:

        # Define variables
        self.r_session = requests.Session()
        self.max_threads = os.cpu_count() * 2

    def _download_wordlist(self, url: str) -> set | None:
        """Download and return wordlist as a set from a single URL"""
        try:
            response = self.r_session.get(url, headers=self.HEADERS, timeout=self.TIMEOUT)
            response.raise_for_status()
            return set(response.text.splitlines())

        except requests.RequestException:
            return set()

    def get_wordlist(self) -> set | None:
        """Download multiple wordlists concurrently and return as a merged set"""
        all_words = set()

        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(self._download_wordlist, url) for url in _Const.WORDLISTS]

                # Collect results and return it
                for future in as_completed(futures):
                    all_words.update(future.result())

            return all_words

        except Exception:
            raise _NoInternetConnection()


class _BruteForceGenerator:
    """Generates brute force combinations with batching and optional filtering."""

    def __init__(
            self,
            min_length,
            max_length,
            filter_func: Optional[Callable[[str], bool]] = None,
            charset: Optional[str] = None,

    ):
        self.charset = charset or "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
        self.min_length = max(1, min_length)
        self.max_length = max(self.min_length, max_length)
        self.filter_func = filter_func

    def estimate_combination_count(self) -> int:
        """
        Estimate the total number of combinations for all lengths in range.
        Returns:
            int: Total combination count.
        """
        total = 0
        charset_len = len(self.charset)
        for length in range(self.min_length, self.max_length + 1):
            total += charset_len ** length
        return total

    def generate_combinations(self, batch_size: int = 1000) -> Generator[List[str], None, None]:
        """
        Generate brute-force combinations in memory-safe batches.

        Args:
            batch_size (int): Number of combinations per batch.

        Yields:
            List[str]: A batch of generated combinations.
        """
        combinations = []
        for length in range(self.min_length, self.max_length + 1):
            for chars in product(self.charset, repeat=length):
                candidate = ''.join(chars)
                if self.filter_func and not self.filter_func(candidate):
                    continue
                combinations.append(candidate)
                if len(combinations) >= batch_size:
                    yield combinations
                    combinations = []
        if combinations:
            yield combinations


class HashRipper(_Const):
    """
    HashRipper: A configurable hash-cracking engine supporting wordlists,
    brute force, multi-threading, and optional GPU acceleration.
    """

    def __init__(self,
                 cli_mode: bool = False,
                 # enable_acceleration: bool = False,
                 custom_wordlist: Union[Tuple[str, ...], List[str], str] = None,
                 max_threads: int = os.cpu_count() * 2,
                 use_bruteforce: bool = False,
                 use_cache: bool = True,
                 use_gpu: bool = False,
                 min_length: int = 4,
                 max_length: int = 10,
                 charset: str = None) -> None:  # Added charset parameter

        # Initialization logic remains the same
        super().__init__()

        self._config = {
            "cli_mode": cli_mode,
            "enable_acceleration": False,
            "custom_wordlist": custom_wordlist,
            "max_threads": max_threads,
            "use_bruteforce": use_bruteforce,
            "use_cache": use_cache,
            "use_gpu": use_gpu and HAS_TORCH,
            "min_length": min_length,
            "max_length": max_length,
            "charset": charset,  # Add charset to config
        }

        # Create handlers
        # self.cache_handler = _CacheHandler()
        self.wordlist_handler = _WordlistHandler()
        self.bruteforce_handler = _BruteForceGenerator(
            min_length=min_length,
            max_length=max_length,
            charset=charset  # Pass charset to bruteforce handler
        )

        if use_gpu:
            self.gpu_accelerator = _GPUAccelerator()
            if not self.gpu_accelerator.available and use_gpu:

                print(f"{Fore.LIGHTMAGENTA_EX}GPU acceleration requested but not available. Falling back to CPU.")
                self._config["use_gpu"] = False

        # Initialize wordlist
        self._wordlist: Set[str] = None
        self._load_wordlists()

    def _load_wordlists(self) -> None:
        """Load wordlists based on configuration."""

        # Add custom wordlist if provided
        custom_wordlist = self._config["custom_wordlist"]

        if custom_wordlist:
            if isinstance(custom_wordlist, str):
                # Load from file
                custom_words = self._load_custom_wordlist(custom_wordlist)
                if custom_words:
                    self._wordlist.update(custom_words)
            else:
                # Add from iterable
                self._wordlist.update(custom_wordlist)

        # Check if cache used and available
        # elif self._config["use_cache"]:
        #     cached_wordlist = self.cache_handler.collect_wordlist()
        #     if cached_wordlist:
        #         self._wordlist = cached_wordlist
        #
        #         # Save the downloaded wordlist in cache if enabled
        #         self.cache_handler.save_cache(self._wordlist)

        if not self._wordlist:
            # Otherwise Load default wordlists
            self._wordlist = self.wordlist_handler.get_wordlist()

    @staticmethod
    def _is_valid_hash(value: bytes | str, length=None) -> bool:
        """
        Check if input is a valid hexadecimal digest or raw binary digest.

        Args:
            value (str | bytes): Hex string, hex bytes, or raw digest.
            length (int, optional): Expected hex length (e.g. 32 for MD5). If None, any valid hex length is allowed.

        Returns:
            bool: True if it's a valid digest, False otherwise.
        """

        if isinstance(value, bytes):
            # If it's raw digest (like from .digest()), convert to hex string
            try:
                value = value.hex()
            except Exception:
                return False
        elif isinstance(value, str):
            value = value.strip()
        else:
            return False

        # Must only contain hex characters
        if not all(c in '0123456789abcdefABCDEF' for c in value):
            return False

        # Length check
        if length is not None and len(value) != length:
            return False

        return True

    def config(self, **kwargs) -> None:
        """
        Update HashRipper configuration at runtime.

        Example:
        """
        for key, value in kwargs.items():
            if key in self._config:
                self._config[key] = value
                # Handle special cases
                if key == "charset" or key == "min_length" or key == "max_length":
                    self.bruteforce_handler = _BruteForceGenerator(
                        charset=self._config["charset"],
                        min_length=self._config["min_length"],
                        max_length=self._config["max_length"]
                    )

    @lru_cache(maxsize=1024)
    def _get_hash(self, data: bytes, hash_func: str) -> bytes:
        """Calculate hash digest for the given data using specified hash function."""
        return self.HASH_FUNCTIONS[hash_func](data).digest()

    def _get_hex_hash(self, data: bytes, hash_func: str) -> str:
        """Calculate hex hash digest for the given data using specified hash function."""
        return self.HASH_FUNCTIONS[hash_func](data).hexdigest()

    def _detect_hash_method(self, hash_digest: bytes) -> str:
        """Detect the hash function type based on digest length."""
        digest_len = len(hash_digest) * 2
        if digest_len not in self.HASHES_LENGTH:
            raise _HashFunctionNotSupported(f"Hash length {digest_len} not supported")
        return self.HASHES_LENGTH[digest_len]

    def _process_wordlist_batch(self,
                                hash_digest: bytes,
                                hash_method: str,
                                words: List[str]) -> Optional[str]:
        """Process a batch of words from the wordlist."""

        for word in words:
            word_bytes = word.encode("utf-8")
            computed_hash = self._get_hash(word_bytes, hash_method)
            if computed_hash == hash_digest:
                return word

        return None

    def _crack_with_wordlist(self,
                             hash_digest: bytes,
                             hex_digest: str,
                             hash_method: str) -> Optional[str]:
        """Attempt to crack the hash using wordlist approach."""

        # Use GPU acceleration if available and enabled
        if self._config["use_gpu"] and hash_method == "md5" and hasattr(self, 'gpu_accelerator') and self.gpu_accelerator.available:
            # This is a simplified approach - actual GPU implementation would be more complex
            batch_results = self.gpu_accelerator.hash_batch_md5(list(self._wordlist))
            if hex_digest in batch_results:
                result = batch_results[hex_digest]
                return result

        # Use threading for CPU-based wordlist processing
        if self._config["enable_acceleration"] and self._config["max_threads"] > 1:

            wordlist = list(self._wordlist)
            batch_size = max(1, len(wordlist) // self._config["max_threads"])
            batches = [wordlist[i:i + batch_size] for i in range(0, len(wordlist), batch_size)]

            with ThreadPoolExecutor(max_workers=self._config["max_threads"]) as executor:
                futures = [
                    executor.submit(self._process_wordlist_batch, hash_digest, hash_method, batch)
                    for batch in batches
                ]

                for future in futures:
                    result = future.result()
                    if result:
                        return result

        else:
            # Single-threaded approach
            for word in self._wordlist:
                word_bytes = word.encode("utf-8")
                computed_hash = self._get_hash(word_bytes, hash_method)
                if computed_hash == hash_digest:
                    return word

        return None

    def _crack_with_bruteforce(self,
                               hash_digest: bytes,
                               hex_digest: str,
                               hash_method: str,
                               total_combinations: int) -> Optional[str]:
        """Attempt to crack the hash using brute force approach with an improved progress bar."""
        # Larger batch size for better performance
        batch_size = 100000  # Increased from 10000 for better throughput

        # # Early return if the hash is in cache
        # if self._config["use_cache"]:
        #     cached_result = self.cache_handler.get_hash_result(hex_digest, hash_method)
        #     if cached_result:
        #         return cached_result

        # Only show progress bar in CLI mode
        if self._config["cli_mode"]:
            print("work")
            try:
                # Format the total with commas for better readability
                formatted_total = f"{total_combinations:,}"

                # Create a more robust progress bar with better formatting
                with tqdm(total=total_combinations,
                          unit="combo",
                          desc=f"Cracking {hash_method}",
                          bar_format="{desc}: {percentage:3.1f}%|{bar:30}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
                          unit_scale=True,
                          miniters=batch_size // 10,  # Update less frequently for better performance
                          dynamic_ncols=True,  # Adjust to terminal width
                          smoothing=0.1) as pbar:  # Smoother progress updates

                    # Call the actual bruteforce implementation with the progress bar
                    result = self._process_combinations_with_progress(
                        hash_digest, hex_digest, hash_method, batch_size, pbar
                    )

                    # Final update to ensure 100% is shown if cracked
                    if result:
                        pbar.update(total_combinations - pbar.n)

                    return result

            except Exception as e:
                # Log the specific error for debugging
                if self._config.get("verbose", False):
                    print(f"Progress bar error: {str(e)}", file=sys.stderr)

                # Fallback if tqdm fails
                return self._bruteforce_without_progress_bar(hash_digest, hex_digest, hash_method, batch_size)
        else:
            # If not in CLI mode, process without showing progress bar
            return self._bruteforce_without_progress_bar(hash_digest, hex_digest, hash_method, batch_size)

    def _process_combinations_with_progress(self,
                                            hash_digest: bytes,
                                            hex_digest: str,
                                            hash_method: str,
                                            batch_size: int,
                                            pbar: 'tqdm') -> Optional[str]:
        """Process combinations with progress tracking in a separate method for better organization."""
        # Pre-compute threading configuration for better performance
        use_threading = self._config["enable_acceleration"] and self._config["max_threads"] > 2
        max_threads = self._config["max_threads"] if use_threading else 2

        # Use a static thread pool to avoid creation/destruction overhead
        executor = ThreadPoolExecutor(max_workers=max_threads) if use_threading else None

        try:
            for batch in self.bruteforce_handler.generate_combinations(batch_size):
                if use_threading:
                    # Optimize batch distribution
                    sub_batch_size = max(1, len(batch) // max_threads)
                    sub_batches = [batch[i:i + sub_batch_size] for i in range(0, len(batch), sub_batch_size)]

                    futures = [
                        executor.submit(self._process_wordlist_batch, hash_digest, hash_method, sub_batch)
                        for sub_batch in sub_batches
                    ]

                    # Process futures as they complete rather than waiting for all
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            return result
                else:
                    # Single-threaded optimization - use batch processing
                    result = self._process_wordlist_batch(hash_digest, hash_method, batch)
                    if result:
                        return result

                # Update progress after processing each batch
                pbar.update(len(batch))

                # Add estimated time display periodically
                if pbar.n % (batch_size * 10) == 0 and pbar.n > 0:
                    # Calculate and format time estimates
                    processed = pbar.n
                    total = pbar.total
                    percent_done = (processed / total) * 100 if total > 0 else 0
                    if percent_done > 0:
                        time_elapsed = pbar.format_dict["elapsed"]
                        estimated_total = time_elapsed / (percent_done / 100)
                        time_remaining = estimated_total - time_elapsed

                        # Format time remaining in a human-readable format
                        days, remainder = divmod(time_remaining, 86400)
                        hours, remainder = divmod(remainder, 3600)
                        minutes, seconds = divmod(remainder, 60)

                        if days > 0:
                            time_str = f"{int(days)}d {int(hours)}h"
                        elif hours > 0:
                            time_str = f"{int(hours)}h {int(minutes)}m"
                        else:
                            time_str = f"{int(minutes)}m {int(seconds)}s"

                        # Update description with estimated time
                        pbar.set_description(f"Bruteforce Progress (Est: {time_str})")

        finally:
            # Ensure executor is properly shutdown
            if executor:
                executor.shutdown(wait=False)

        return None

    def _bruteforce_without_progress_bar(self,
                                         hash_digest: bytes,
                                         hex_digest: str,
                                         hash_method: str,
                                         batch_size: int) -> Optional[str]:
        """Helper method for brute force without progress bar."""
        processed = 0
        progress_interval = 1000000  # Log progress every million combinations

        for batch in self.bruteforce_handler.generate_combinations(batch_size):
            if self._config["enable_acceleration"] and self._config["max_threads"] > 1:
                sub_batch_size = max(1, len(batch) // self._config["max_threads"])
                sub_batches = [batch[i:i + sub_batch_size] for i in range(0, len(batch), sub_batch_size)]

                with ThreadPoolExecutor(max_workers=self._config["max_threads"]) as executor:
                    futures = [
                        executor.submit(self._process_wordlist_batch, hash_digest, hash_method, sub_batch)
                        for sub_batch in sub_batches
                    ]

                    for future in futures:
                        result = future.result()
                        if result:
                            return result
            else:
                # Single-threaded approach
                for word in batch:
                    word_bytes = word.encode("utf-8")
                    computed_hash = self._get_hash(word_bytes, hash_method)
                    if computed_hash == hash_digest:
                        return word

        return None

    def crack(self, hash_input: Union[bytes, str]) -> Dict[str, Union[str, None, float]]:
        """
        Crack the given hash digest.

        Args:
            hash_input: The hash to crack, either as bytes or hex string

        Returns:
            Dictionary containing:
                - plaintext: The cracked plaintext or None if not found
                - hash_method: The detected hash method
                - time_taken: Time taken in seconds
                - successful: Whether the cracking was successful
        """
        start_time = perf_counter()

        # Check is valid hash
        if not self._is_valid_hash(hash_input):
            raise _HashIsNotValid()

        if self._config["cli_mode"]:
            print(f"{Fore.MAGENTA}[*] - HashRipper - V {self.VERSION} initialized with "
                  f"{self._get_friendly_num(len(self._wordlist))} words")

        if isinstance(hash_input, str):
            try:
                # Assume it's a hex string
                hash_digest = bytes.fromhex(hash_input)
                hex_digest = hash_input.lower()  # Normalize to lowercase
            except ValueError:
                return {
                    "password": None,  # Added for consistency
                    "hash_method": None,
                    "time_taken": perf_counter() - start_time,  # Fixed to use perf_counter
                    "successful": False,
                    "error": "Invalid hex string provided"
                }
        else:
            # It's already bytes
            hash_digest = hash_input
            hex_digest = hash_digest.hex()

        try:
            # Detect hash method
            hash_method = self._detect_hash_method(hash_digest)

            if self._config["cli_mode"]:
                print(f"{Fore.LIGHTGREEN_EX}[*] - Detected hash method: {hash_method} .")

            # First try wordlist approach
            result = self._crack_with_wordlist(hash_digest, hex_digest, hash_method)

            # If not found and bruteforce is enabled, try that
            if result is None and self._config["use_bruteforce"]:
                # Get the total combination estimation
                total_combinations: int = self.bruteforce_handler.estimate_combination_count()

                if self._config["cli_mode"]:
                    print(f"{Fore.LIGHTRED_EX}[-] - Wordlist approach failed, trying brute force...")

                    print(f"{Fore.LIGHTGREEN_EX}[*] - Crack with bruteforce passwords count : "
                          f"{self._get_friendly_num(total_combinations)}")

                result = self._crack_with_bruteforce(hash_digest, hex_digest, hash_method, total_combinations)

            time_taken = round(perf_counter() - start_time, 4)

            return {
                "password": result,
                "hash_method": hash_method,
                "time_taken": time_taken,
                "successful": result is not None,
                "error": None
            }

        except _HashFunctionNotSupported as e:
            return {
                "password": None,
                "hash_method": None,
                "time_taken": round(perf_counter() - start_time, 4),
                "successful": False,
                "error": str(e)
            }
        except Exception as e:
            if self._config["cli_mode"]:
                print(f"Error during hash cracking: {e}")

            return {
                "password": None,
                "hash_method": None,
                "time_taken": round(perf_counter() - start_time, 4),
                "successful": False,
                "error": str(e)
            }

    @staticmethod
    def _load_custom_wordlist(file_name: str) -> Set[str]:
        """Load custom wordlist from a file."""
        if os.path.exists(file_name):
            try:
                with open(file_name, "r", encoding="utf-8", errors="ignore") as f:
                    return {line.strip() for line in f if line.strip()}
            except Exception as e:
                logging.error(f"Error loading custom wordlist {file_name}: {e}")
        return set()

    @staticmethod
    def _get_friendly_num(value: int) -> str:
        """Return a human-friendly number format (e.g., 1.2M, 3.4B)."""
        suffixes = ['', 'K', 'M', 'B', 'T', 'Q']
        magnitude = 0
        while abs(value) >= 1000 and magnitude < len(suffixes) - 1:
            magnitude += 1
            value /= 1000.0

        return f"{value:.2f}{suffixes[magnitude]}"

    @property
    def version(self) -> str:
        """Return current HashRipper version."""
        return self.VERSION

    @property
    def stats(self) -> Dict[str, Union[int, bool, list]]:
        """Return statistics about the current HashRipper instance."""
        return {
            "wordlist_size": len(self._wordlist),
            "using_gpu": self._config["use_gpu"] and (
                        hasattr(self, 'gpu_accelerator') and self.gpu_accelerator.available),
            "max_threads": self._config["max_threads"],
            "bruteforce_enabled": self._config["use_bruteforce"],
            "cache_enabled": self._config["use_cache"],
            "min_bruteforce_length": self._config["min_length"],
            "max_bruteforce_length": self._config["max_length"],
            "supported_hash_types": list(self.HASH_FUNCTIONS.keys())
        }


class _CLI(_Const):
    """Command-line interface for HashRipper application."""

    def __init__(self):
        """Initialize CLI with terminal settings and HashRipper instance."""
        super(_CLI, self).__init__()

        # Initialize colorama
        colorama.init(autoreset=True)
        # Get the terminal width
        self.terminal_width = shutil.get_terminal_size()[0]
        self.platform_name = sys.platform

        # Create HashRipper object
        self.ripper = HashRipper(cli_mode=True)

        # Save original config for reset option
        self.original_config = copy.deepcopy(self.ripper._config)

        # Define and set the console title
        console_title = f"HashRipper - V {self.VERSION}"
        self._set_terminal_title(console_title)

        # Command mapping for more flexible command handling
        self.commands = {
            "\\help": self._show_help,
            "help": self._show_help,
            "\\version": self._show_version,
            "\\about": self._show_about,
            "\\config": self._show_config,
            "\\settings": self._show_config,  # Alias for config
            "\\exit": self._exit_app,
            "\\quit": self._exit_app,
            "\\q": self._exit_app,
            "\\bye": self._exit_app,
            "exit": self._exit_app,
            "quit": self._exit_app,
            "q": self._exit_app,
            "bye": self._exit_app
        }

    def run(self):
        """Run the CLI application main loop."""
        # Clear console
        self._clear_screen()

        # Show header
        self._display_header()

        # Handle the user input
        self._handle_user_input()

    def _print_centered(self, text, color=Fore.WHITE):
        """Print text centered in terminal.

        Args:
            text (str): Text to center and print
            color (str): Color to use for text
        """
        print(f"{color}{text.center(self.terminal_width)}")

    def _display_header(self):
        """Display the application header."""
        print()
        self._print_centered(f"╭{'─' * (self.terminal_width - 4)}╮", Fore.MAGENTA)

        # Logo line
        logo = " HashRipper "
        version_str = f"V {self.VERSION} "

        # Calculate the padding values
        padding = self.terminal_width - len(logo) - len(version_str) - 4

        # Print it
        print(f"  {Fore.MAGENTA}{Fore.CYAN}{Style.BRIGHT}{logo}{' ' * padding}{version_str}{Fore.MAGENTA}")
        self._print_centered(f"╰{'─' * (self.terminal_width - 4)}╯", Fore.MAGENTA)

    def _handle_user_input(self):
        """Handle user input and process commands or hash cracking."""
        try:
            # Print configuration data
            print(f" {Fore.LIGHTMAGENTA_EX} * Custom Wordlist   : {self.ripper._config['custom_wordlist'] if 
                    self.ripper._config['custom_wordlist'] else 'No'}\n"
                  
                  f"  * GPU Acceleration  : {'Yes' if self.ripper._config['use_gpu'] else 'No'}\n"
                  f"  * BruteForce Attack : {'Yes' if self.ripper._config['use_bruteforce'] else 'No'}\n")

            print(f"{Fore.LIGHTWHITE_EX}  Type 'help' or '\\help' to get explanation")

            # Show the user input prompt
            user_input = input("\n  ## : ").strip()

            # Print separator
            print(f"\n{Fore.MAGENTA}{'─' * self.terminal_width}\n")

            # Handle empty input
            if not user_input:
                self._print_text("Please enter a hash value or command.", color=Fore.YELLOW)
                self._wait_for_key()
                self.run()
                return

            # Check if the entered input is a command
            if user_input.lower() in self.commands:
                self.commands[user_input.lower()]()
                self._wait_for_key()
                self.run()
                return
            elif user_input.startswith("\\"):
                self._print_text(f"Unknown command: {user_input}\nType '\\help' for available commands.",
                                 color=Fore.YELLOW)
                self._wait_for_key()
                self.run()
                return

            # Otherwise try to crack the given hash
            self._crack_hash(user_input)

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Operation cancelled by user.")
            self._exit_app()
        except Exception as e:
            self._print_text(f"Unexpected error: {str(e)}", color=Fore.LIGHTRED_EX)

        self._wait_for_key()
        self.run()

    def _crack_hash(self, hash_value):
        """Attempt to crack the provided hash value.

        Args:
            hash_value (str): Hash to crack
        """
        try:
            result = self.ripper.crack(hash_value)

            # Check if crack successful
            if result["successful"]:
                print(f"\n{Fore.GREEN}[+] - Hash cracked successfully!")
                print(f"{Fore.GREEN}[+] - Password: {Fore.MAGENTA}{Style.BRIGHT}{result['password']}")
                print(f"{Fore.GREEN}[+] - Time taken: {result['time_taken']}")
            else:
                print(f"\n{Fore.YELLOW}[-] - Hash not found in dictionary.")
                print(f"{Fore.YELLOW}[-] - Time elapsed: {result['time_taken']}")

        except _HashFunctionNotSupported:
            self._print_text("Error: The hash algorithm is not supported.", color=Fore.LIGHTRED_EX)
        except _HashIsNotValid:
            self._print_text("Error: The input is not a valid hash value.", color=Fore.LIGHTRED_EX)
        except Exception as e:
            self._print_text(f"Error: {str(e)}", color=Fore.LIGHTRED_EX)

    @staticmethod
    def _exit_app() -> None:
        """Exit the application gracefully."""

        print(f"\n{Fore.MAGENTA}  Thank you for using HashRipper!\n  Goodbye.")
        sleep(1)
        sys.exit(0)

    @staticmethod
    def _wait_for_key() -> None:
        """Wait for user to press Enter to continue."""

        print(f"\n  {Fore.WHITE}Press Enter to continue...{Style.RESET_ALL}", end="")
        input()
        sleep(0.2)  # Reduced sleep time for better responsiveness

    @staticmethod
    def _print_text(text, color=Fore.LIGHTMAGENTA_EX, style=Style.NORMAL) -> None:
        """Show text with custom color and style.

        Args:
            text (str): Text to display
            color: Text color to use
            style: Text style to apply
        """
        print(f"{color}{style}{text}")

    @staticmethod
    def _show_help() -> None:
        """Display help information."""

        help_text = f"""
        {Style.BRIGHT}{Fore.CYAN}AVAILABLE COMMANDS:{Style.RESET_ALL}
        
        {Fore.WHITE}\\help{Fore.GREEN} - Show this help message
        {Fore.WHITE}\\version{Fore.GREEN} - Show version information
        {Fore.WHITE}\\about{Fore.GREEN} - Show information about HashRipper
        {Fore.WHITE}\\config{Fore.GREEN} - Show and modify configuration settings
        {Fore.WHITE}\\settings{Fore.GREEN} - Alias for \\config
        {Fore.WHITE}\\exit, \\quit, \\q{Fore.GREEN} - Exit the application
        
        {Style.BRIGHT}{Fore.CYAN}USAGE:{Style.RESET_ALL}
        
        {Fore.GREEN}Simply type or paste your hash value at the prompt.
        HashRipper will attempt to crack it using the configured methods.
        
        {Style.BRIGHT}{Fore.CYAN}CONFIGURATION:{Style.RESET_ALL}
        
        {Fore.GREEN}Use the \\config command to change settings such as:
        - Custom wordlist path
        - GPU acceleration
        - Brute force options
        - Dictionary attack settings
        
        {Style.BRIGHT}{Fore.CYAN}SUPPORTED HASH TYPES:{Style.RESET_ALL}
        
        {Fore.GREEN}- MD5
        - SHA1
        - SHA256
        - SHA512
        - More based on your implementation...
            """
        print(help_text)

    def _show_version(self) -> None:
        """Display version information."""
        print(f"\n  {Style.BRIGHT}{Fore.CYAN}VERSION INFO:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}HashRipper v{self.VERSION}")
        print(f"  {Fore.GREEN}Build date: {self.DATE}")

    @staticmethod
    def _show_about() -> None:
        """Display information about the application."""

        about_text = f"""
        {Style.BRIGHT}{Fore.CYAN}ABOUT HashRipper:{Style.RESET_ALL}
        
        {Fore.GREEN}HashRipper is a powerful hash cracking utility designed for
        security professionals, researchers, and system administrators.
        
        {Fore.GREEN}Created by: Aymen Brahim Djelloul
        look  : https://github.com/aymenbrahimdjelloul/HashRipper
        License : MIT
            """
        print(about_text)

    def _show_config(self) -> None:
        """Display current configuration settings and allow modification."""
        while True:
            self._clear_screen()
            self._display_header()

            print(f"\n  {Style.BRIGHT}{Fore.CYAN}CONFIGURATION SETTINGS:{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}Modify settings to customize HashRipper's behavior\n")

            # Display all configuration settings with numbers
            config_keys = list(self.ripper._config.keys())
            for i, key in enumerate(config_keys, 0):
                value = self.ripper._config[key]

                # Skip cli mode
                if key == "cli_mode":
                    continue

                value_display = str(value)
                # Format boolean values for better readability
                if isinstance(value, bool):
                    color = Fore.GREEN if value else Fore.RED
                    value_display = f"{color}{value}"
                # Format file paths or special values
                elif key == "custom_wordlist" and value:
                    value_display = f"{Fore.BLUE}{value}"
                    # Check if file exists and show indicator
                    if not os.path.isfile(value):
                        value_display += f" {Fore.RED}(file not found)"

                print(f"  {Fore.WHITE}[{i}] {key}: {value_display}")

            # Add options menu
            print(f"\n  {Style.BRIGHT}{Fore.WHITE}ACTIONS:{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}[S] {Fore.YELLOW}Save configuration to file")
            print(f"  {Fore.WHITE}[L] {Fore.YELLOW}Load configuration from file")
            print(f"  {Fore.WHITE}[R] {Fore.YELLOW}Reset to default settings")
            print(f"  {Fore.WHITE}[0] {Fore.YELLOW}Return to main menu")

            # Get user choice
            try:
                choice = input(f"\n  {Fore.CYAN}Enter option (number, S, L, R, or 0): {Fore.WHITE}").strip().upper()

                # Handle special commands
                if choice == "0":
                    return
                elif choice == "S":
                    self._save_config()
                    continue
                elif choice == "L":
                    self._load_config()
                    continue
                elif choice == "R":
                    self._reset_config()
                    continue

                # Handle numeric choices for editing settings
                try:
                    choice_idx = int(choice) - 1
                    if choice_idx < 0 or choice_idx >= len(config_keys):
                        raise ValueError("Invalid selection")

                    # Get the key to modify
                    key_to_modify = config_keys[choice_idx]
                    current_value = self.ripper._config[key_to_modify]

                    # Handle different types of settings
                    if isinstance(current_value, bool):
                        # Toggle boolean values
                        new_value = not current_value
                        self.ripper._config[key_to_modify] = new_value
                        print(f"\n  {Fore.GREEN}✓ Changed {key_to_modify} to {new_value}")

                    elif key_to_modify == "custom_wordlist":
                        # Handle file path selection
                        print(f"\n  {Fore.CYAN}Current wordlist: {Fore.WHITE}{current_value}")
                        print(f"  {Fore.YELLOW}Enter new wordlist path or leave empty to cancel:")
                        new_path = input(f"  {Fore.WHITE}> ")

                        if new_path.strip():
                            # Validate the file exists
                            if os.path.isfile(new_path):
                                self.ripper._config[key_to_modify] = new_path
                                print(f"\n  {Fore.GREEN}✓ Wordlist updated to: {new_path}")
                            else:
                                print(f"\n  {Fore.RED}✗ File not found: {new_path}")
                                print(f"  {Fore.YELLOW}Press any key to continue anyway, or Ctrl+C to cancel")
                                try:
                                    input()
                                    self.ripper._config[key_to_modify] = new_path
                                    print(f"\n  {Fore.YELLOW}⚠ Wordlist path set but file not found")
                                except KeyboardInterrupt:
                                    print(f"\n  {Fore.YELLOW}Operation cancelled")
                                    sleep(1)
                                    continue

                    else:
                        # Handle other types of settings
                        print(f"\n  {Fore.CYAN}Current value: {Fore.WHITE}{current_value}")
                        print(f"  {Fore.YELLOW}Enter new value or leave empty to cancel:")
                        new_value = input(f"  {Fore.WHITE}> ")

                        if new_value.strip():
                            # Try to convert to the same type as the current value
                            try:
                                if isinstance(current_value, int):
                                    new_value = int(new_value)
                                elif isinstance(current_value, float):
                                    new_value = float(new_value)

                                self.ripper._config[key_to_modify] = new_value
                                print(f"\n  {Fore.GREEN}✓ Setting updated")
                            except ValueError:
                                print(f"\n  {Fore.RED}✗ Invalid value format")
                                sleep(1.5)

                    # Pause to show the change confirmation
                    sleep(1)

                except (ValueError, IndexError):
                    print(f"\n  {Fore.RED}✗ Invalid selection. Please enter a number between 0 and {len(config_keys)}")
                    sleep(1.5)

            except KeyboardInterrupt:
                return

    def _save_config(self) -> None:
        """Save current configuration to a file."""

        try:
            print(f"\n  {Fore.CYAN}Enter filename to save configuration (default: hashripper.conf):")
            filename = input(f"  {Fore.WHITE}> ").strip() or "hashripper.conf"

            # Add .conf extension if not present
            if not filename.endswith('.conf'):
                filename += '.conf'

            # Create a config file with a simple format
            with open(filename, 'w') as f:
                f.write("# HashRipper Configuration File\n")
                f.write(f"# Generated by HashRipper v{self.VERSION}\n\n")

                for key, value in self.ripper._config.items():
                    f.write(f"{key}={value}\n")

            print(f"\n  {Fore.GREEN}✓ Configuration saved to {filename}")
            sleep(1.5)

        except Exception as e:
            print(f"\n  {Fore.RED}✗ Error saving configuration: {str(e)}")
            sleep(2)

    def _load_config(self) -> None:
        """Load configuration from a file."""

        try:
            print(f"\n  {Fore.CYAN}Enter filename to load configuration (default: hashripper.conf):")
            filename = input(f"  {Fore.WHITE}> ").strip() or "hashripper.conf"

            # Check if file exists
            if not os.path.isfile(filename):
                print(f"\n  {Fore.RED}✗ File not found: {filename}")
                sleep(1.5)
                return

            # Read and parse the config file
            new_config = {}
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse key=value pairs
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        # Convert value to appropriate type
                        if key in self.ripper._config:
                            original_type = type(self.ripper._config[key])
                            try:
                                if original_type == bool:
                                    # Handle boolean values
                                    value = value.lower() in ('true', '1', 'yes', 'y')
                                elif original_type == int:
                                    value = int(value)
                                elif original_type == float:
                                    value = float(value)
                                # String values don't need conversion

                                new_config[key] = value
                            except (ValueError, TypeError):
                                print(f"\n  {Fore.YELLOW}⚠ Skipping invalid value for {key}: {value}")

            # Update config with new values
            if new_config:
                for key, value in new_config.items():
                    if key in self.ripper._config:
                        self.ripper._config[key] = value

                print(f"\n  {Fore.GREEN}✓ Configuration loaded from {filename}")
            else:
                print(f"\n  {Fore.YELLOW}⚠ No valid settings found in {filename}")

            sleep(1.5)

        except Exception as e:
            print(f"\n  {Fore.RED}✗ Error loading configuration: {str(e)}")
            sleep(2)

    def _reset_config(self) -> None:
        """Reset configuration to default values."""

        try:
            print(f"\n  {Fore.YELLOW}⚠ Are you sure you want to reset all settings to defaults? (y/N)")
            confirm = input(f"  {Fore.WHITE}> ").strip().lower()

            if confirm in ('y', 'yes'):
                # Restore from original config saved during initialization
                self.ripper._config = copy.deepcopy(self.original_config)
                print(f"\n  {Fore.GREEN}✓ Settings reset to defaults")
            else:
                print(f"\n  {Fore.YELLOW}⚠ Reset cancelled")

            sleep(1.5)

        except Exception as e:
            print(f"\n  {Fore.RED}✗ Error resetting configuration: {str(e)}")
            sleep(2)

    def _clear_screen(self) -> None:
        """Clear the terminal screen based on platform."""

        if self.platform_name == "win32":
            os.system("cls")
        else:
            os.system("clear")

    def _set_terminal_title(self, title) -> None:
        """Set terminal title based on platform.

        Args:
            title (str): Title to set for the terminal window
        """
        if self.platform_name == 'win32':
            os.system(f"title {title}")
        else:
            pass


class _HashFunctionNotSupported(BaseException):
    """ This class is exception when enter a no supported hash method"""

    def __str__(self) -> str:
        return (f"HashRipper cannot detect the hash function These is the supported functions "
                f":\n {_Const.SUPPORTED_HASH_FUNCTIONS}")


class _HashIsNotValid(BaseException):

    def __str__(self):
        return "The hash you entered is not valid !"


class _NoInternetConnection(BaseException):
    """ This method is exception raised when internet connection is failed"""

    def __str__(self):
        return "HashRipper cannot download online wordlist ! Please check your internet connect ."


def _main():
    """ This function will start the CLI"""

    # Create CLI object
    cli = _CLI()
    # Run the CLI app
    cli.run()


def _log_unhandled_exception(exc_type, exc_value, exc_traceback):
    """ This function will create log errors file to track errors"""

    os.makedirs("errors", exist_ok=True)
    log_file = os.path.join("errors", f"error_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")

    with open(log_file, "w") as f:
        f.write("Unhandled Exception:\n")
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)

    print(f"\n[!] Error logged to: {log_file}")
    sys.exit(1)


if __name__ == "__main__":
    # Hook to catch all unhandled exceptions
    sys.excepthook = _log_unhandled_exception

    # Run the CLI application
    _main()
