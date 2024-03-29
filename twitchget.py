"""twitchget

Usage: twitchget.py <target> <download_dir>
"""
import base64
import json
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

import win32crypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from docopt import docopt


CHROME_USERDATA_PATH = Path.home() / "AppData/Local/Google/Chrome/User Data"
CHROME_LOCALSTATE_PATH = CHROME_USERDATA_PATH / "Local State"
CHROME_COOKIES_PATH = CHROME_USERDATA_PATH / "Default/Network/Cookies"
HOST_KEY = ".twitch.tv"
COOKIES_BLACKLIST = ("_ga")
COOKIES_TXT_PATH = Path(__file__).parent.resolve() / "cookies.txt"


def get_encryption_key(chrome_local_state_path):
    """Get the key used to symmetrically (AESGCM) encrypt cookie values in v10 from Chrome Local State."""
    # Load the base64 encoded encrypted key from Chrome Local State json
    with chrome_local_state_path.open("r", encoding="utf-8") as f:
        base64_encrypted_key = json.load(f)["os_crypt"]["encrypted_key"]
    # Decode the encrypted key, remove the "DPAPI" marker at the start, and decrypt
    encrypted_key = base64.b64decode(base64_encrypted_key)[5::]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]


def get_cookies(cookies_db_path, host_key, aes_gcm_key):
    """Get the cookies for the specified host_key from Chrome Cookies sqlite database."""
    cookies = []
    with tempfile.TemporaryDirectory(prefix="twitchget_") as temp_dir:
        # Copy the cookies database to avoid hitting a lock and open
        cookies_db_copy_path = shutil.copy(cookies_db_path, temp_dir)
        db = sqlite3.connect(cookies_db_copy_path)
        db.text_factory = bytes
        query = "SELECT name, path, expires_utc, is_secure, encrypted_value "\
                "FROM cookies WHERE host_key=?"
        cursor = db.cursor()
        cursor.execute(query, (host_key,))
        for result in cursor.fetchall():
            name, path, expiry, secure, ev = result
            # Skip cookies that are blacklisted by name or session-only
            if name.decode("utf-8") in COOKIES_BLACKLIST or expiry == 0:
                continue
            # Decrypt the cookie value
            if ev.startswith(b"v10"):
                nonce, cipertext = ev[3:15], ev[15:]
                aes_gcm = AESGCM(aes_gcm_key)
                dv = aes_gcm.decrypt(nonce, cipertext, None).decode("utf-8")
            else:
                dv = win32crypt.CryptUnprotectData(ev, None, None, None, 0)[1].decode("utf-8")
            cookies.append((name.decode("utf-8"), path.decode("utf-8"), expiry, secure, dv))
        # Close the database cleanly
        db.close()
    return cookies


def write_cookies_file(cookies, cookies_txt_path):
    """Write cookies in the Netscape cookies.txt format."""
    # Write cookies to Netscape cookies.txt format as per
    # https://unix.stackexchange.com/questions/36531/format-of-cookies-when-using-wget
    with cookies_txt_path.open(mode="w", encoding="utf-8") as cf:
        cf.write("# HTTP Cookie File\n")
        for cookie in cookies:
            name, path, expiry, secure, dv = cookie
            # Convert the secure integer to TRUE/FALSE
            secure = "TRUE" if secure else "FALSE"
            if dv:
                cf.write(f"{HOST_KEY}\tTRUE\t{path}\t{secure}\t{expiry}\t{name}\t{dv}\n")


def run_ytdl(target, cookies_txt_path, download_dir):
    """Run a youtube-dl.exe subprocess that uses the extracted cookies."""
    ytdl_args = ["youtube-dl.exe", "-f 720p", target, f"--cookies={cookies_txt_path}",
                 f"--output={download_dir}\\%(title)s.%(ext)s"]
    subprocess.run(ytdl_args)


if __name__ == '__main__':
    args = docopt(__doc__)
    target, download_dir = args["<target>"], args["<download_dir>"]

    # Extract and decrypt the os_crypt.encrypted_key from Chrome Local State
    aes_gcm_key = get_encryption_key(CHROME_LOCALSTATE_PATH)
    # Get current cookies for ".twitch.tv" from Chrome default profile Cookies sqlite database
    cookies = get_cookies(CHROME_COOKIES_PATH, HOST_KEY, aes_gcm_key)
    # Write the cookies to a youtube-dl compliant Netscape cookies.txt format
    write_cookies_file(cookies, COOKIES_TXT_PATH)
    # Run youtube-dl against the target, using cookies at COOKIES_TXT_PATH and downloading to download_dir
    run_ytdl(target, COOKIES_TXT_PATH, download_dir)
