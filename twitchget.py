"""twitchget

Usage: twitchget.py <target> <download_dir>
"""
import shutil
import sqlite3
import subprocess
from pathlib import Path

import win32crypt
from docopt import docopt


SCRIPT_DIR = Path(__file__).parent.resolve()
HOST_KEY = ".twitch.tv"


def _get_cookies(cookies_db_path, host_key):
    cookies = []
    # Copy the cookies database locally to avoid hitting a lock if Chrome has its copy open
    cookies_db_copyp = shutil.copy(cookies_db_path, SCRIPT_DIR)
    # Open the local copy of the cookies database
    db = sqlite3.connect(cookies_db_copyp)
    cursor = db.cursor()
    # Select desired columns in rows from database where host_key
    params = (host_key,)
    cursor.execute("SELECT name, path, expires_utc, is_secure, encrypted_value FROM cookies WHERE host_key=?", params)
    for result in cursor.fetchall():
        name, path, expiry, secure, ev = result[0:5]
        # Decrypt the cookie value
        dv = win32crypt.CryptUnprotectData(ev, None, None, None, 0)[1].decode("utf-8")
        cookies.append((name, path, expiry, secure, dv))
    # Close the database cleanly
    db.close()
    # Unlink/remove the local cookies database copy
    Path(cookies_db_copyp).unlink()
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
            cf.write(f"{HOST_KEY}\tTRUE\t{path}\t{secure}\t{expiry}\t{name}\t{dv}\n")
    return cookies_txt_p


def _run_ytdl(target, cookies_txt_p, download_dir):
    ytdl_args = ["youtube-dl.exe", target, f"--cookies={cookies_txt_p}",
                 f"--output={download_dir}\\%(title)s.%(ext)s"]
    subprocess.run(ytdl_args)


if __name__ == '__main__':
    args = docopt(__doc__)
    target, download_dir = args["<target>"], args["<download_dir>"]

    chrome_cookies_p = Path.home() / "AppData/Local/Google/Chrome/User Data/Default/Cookies"
    # Get current cookies for ".twitch.tv" from Chrome default profile Cookies sqlite database
    cookies = _get_cookies(chrome_cookies_p, HOST_KEY)
    # Filter out cookies that are not wanted and/or required
    cookies = _filter_cookies(cookies)
    # Write the cookies to a youtube-dl compliant Netscape cookies.txt format
    cookies_txt_p = _write_cookies_file(cookies)
    # Run youtube-dl against the target, using cookies at cookies_txt_p and downloading to download_dir
    _run_ytdl(target, cookies_txt_p, download_dir)
