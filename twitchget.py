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


SCRIPT_DIR = Path(__file__).parent.resolve()
CHROME_USERDATA_PATH = Path.home() / "AppData/Local/Google/Chrome/User Data"
CHROME_LOCALSTATE_PATH = CHROME_USERDATA_PATH / "Local State"
CHROME_COOKIES_PATH = CHROME_USERDATA_PATH / "Default/Cookies"
HOST_KEY = ".twitch.tv"


def _get_encryption_key(chrome_local_state_path):
    # Open the Chrome Local State as json and get the os_crypt.encrypted_key
    with chrome_local_state_path.open("r", encoding="utf-8") as f:
        base64_encrypted_key = json.load(f)["os_crypt"]["encrypted_key"]
    # Decode the encrypted key from base64 and remove the "DPAPI" marker at the start
    encrypted_key = base64.b64decode(base64_encrypted_key)[5::]
    # Decrypt the encrypted key
    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return key


def _get_cookies(cookies_db_path, host_key, aes_gcm_key):
    cookies = []
    with tempfile.TemporaryDirectory(prefix="twitchget_") as temp_dir:
        # Copy the cookies database temporarily to avoid hitting a lock if Chrome has its copy open
        cookies_db_copyp = shutil.copy(cookies_db_path, temp_dir)
        # Open the local copy of the cookies database
        db = sqlite3.connect(cookies_db_copyp)
        cursor = db.cursor()
        # Select desired columns in rows from database where host_key
        params = (host_key,)
        query = "SELECT name, path, expires_utc, is_secure, encrypted_value "\
                "FROM cookies WHERE host_key=?"
        cursor.execute(query, params)
        for result in cursor.fetchall():
            name, path, expiry, secure, ev = result
            # Decrypt the cookie value
            if ev.startswith(b"v10"):
                nonce, cipertext = ev[3:15], ev[15:]
                aes_gcm = AESGCM(aes_gcm_key)
                dv = aes_gcm.decrypt(nonce, cipertext, None).decode("utf-8")
            else:
                dv = win32crypt.CryptUnprotectData(ev, None, None, None, 0)[1].decode("utf-8")
            cookies.append((name, path, expiry, secure, dv))
        # Close the database cleanly
        db.close()
    return cookies


def _filter_cookies(cookies):
    # Filter out session-only (non-persistent) cookies
    cookies = filter(lambda c: c[2] != 0, cookies)
    # Filter out blacklisted cookies by name
    blacklist = ["_ga"]
    cookies = filter(lambda c: c[0] not in blacklist, cookies)
    return cookies


def _write_cookies_file(cookies):
    cookies_txt_p = SCRIPT_DIR / "cookies.txt"
    # Write cookies to Netscape cookies.txt format as per
    # https://unix.stackexchange.com/questions/36531/format-of-cookies-when-using-wget
    with cookies_txt_p.open(mode="w", encoding="utf-8") as cf:
        cf.write("# HTTP Cookie File\n")
        for cookie in cookies:
            name, path, expiry, secure, dv = cookie
            # Convert the secure integer to TRUE/FALSE
            secure = "TRUE" if secure else "FALSE"
            if dv:
                cf.write(f"{HOST_KEY}\tTRUE\t{path}\t{secure}\t{expiry}\t{name}\t{dv}\n")
    return cookies_txt_p


def _run_ytdl(target, cookies_txt_p, download_dir):
    ytdl_args = ["youtube-dl.exe", target, f"--cookies={cookies_txt_p}",
                 f"--output={download_dir}\\%(title)s.%(ext)s"]
    subprocess.run(ytdl_args)


if __name__ == '__main__':
    args = docopt(__doc__)
    target, download_dir = args["<target>"], args["<download_dir>"]

    # Extract and decrypt the os_crypt.encrypted_key from Chrome Local State
    aes_gcm_key = _get_encryption_key(CHROME_LOCALSTATE_PATH)
    # Get current cookies for ".twitch.tv" from Chrome default profile Cookies sqlite database
    cookies = _get_cookies(CHROME_COOKIES_PATH, HOST_KEY, aes_gcm_key)
    # Filter out cookies that are not wanted and/or required
    cookies = _filter_cookies(cookies)
    # Write the cookies to a youtube-dl compliant Netscape cookies.txt format
    cookies_txt_p = _write_cookies_file(cookies)
    # Run youtube-dl against the target, using cookies at cookies_txt_p and downloading to download_dir
    _run_ytdl(target, cookies_txt_p, download_dir)
