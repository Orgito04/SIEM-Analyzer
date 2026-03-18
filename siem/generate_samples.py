#!/usr/bin/env python3
"""
Generate realistic sample log files for testing the SIEM analyzer.
Creates auth.log, access.log, and events.json with real attack patterns.
"""

import os
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

Path("sample_logs").mkdir(exist_ok=True)

BASE_TS = datetime(2024, 3, 15, 0, 0, 0)

def ts(offset_seconds: int) -> str:
    dt = BASE_TS + timedelta(seconds=offset_seconds)
    return dt.strftime("%b %d %H:%M:%S")

def web_ts(offset_seconds: int) -> str:
    dt = BASE_TS + timedelta(seconds=offset_seconds)
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


# ── auth.log ────────────────────────────────────────────────────────────────
auth_lines = []

# Brute force from 192.168.1.100
for i in range(60):
    user = random.choice(["root", "admin", "ubuntu", "pi", "deploy"])
    auth_lines.append((i * 5, f"sshd[1234]: Failed password for {user} from 192.168.1.100 port {40000+i} ssh2"))

# Brute force from second IP
for i in range(25):
    auth_lines.append((i * 8 + 10, f"sshd[1234]: Failed password for root from 10.0.0.55 port {50000+i} ssh2"))

# Successful SSH login (suspicious - off hours at 3am)
auth_lines.append((3*3600, "sshd[1234]: Accepted password for ubuntu from 203.0.113.42 port 51234 ssh2"))

# New IP login
auth_lines.append((6*3600, "sshd[1234]: Accepted password for ubuntu from 198.51.100.9 port 59999 ssh2"))

# Privilege escalation
auth_lines.append((6*3600 + 30, "sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash"))
auth_lines.append((6*3600 + 45, "sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/etc/shadow"))
auth_lines.append((6*3600 + 60, "sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/nmap -sV 10.0.0.0/8"))
auth_lines.append((6*3600 + 90, "su: (to root) ubuntu on pts/0"))

# Password spray (one IP → many users)
spray_users = ["alice", "bob", "charlie", "diana", "eve", "frank", "grace", "hank"]
for i, u in enumerate(spray_users):
    auth_lines.append((7200 + i*30, f"sshd[1234]: Failed password for invalid user {u} from 185.220.101.5 port {60000+i} ssh2"))

# Repeated sudo (frequency alert)
for i in range(12):
    auth_lines.append((8*3600 + i*60, f"sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/ls /root"))

# Normal logins (daytime)
for i in range(8):
    auth_lines.append((9*3600 + i*1800, f"sshd[1234]: Accepted password for alice from 10.10.1.50 port {44000+i} ssh2"))

# Sort and write
auth_lines.sort(key=lambda x: x[0])
with open("sample_logs/auth.log", "w") as fh:
    hostname = "server01"
    for offset, msg in auth_lines:
        fh.write(f"{ts(offset)} {hostname} {msg}\n")

print(f"✓ sample_logs/auth.log  ({len(auth_lines)} lines)")


# ── access.log ──────────────────────────────────────────────────────────────
web_lines = []

def web_line(offset, ip, method, path, status, bytes_=512, ua="Mozilla/5.0"):
    return (offset, f'{ip} - - [{web_ts(offset)}] "{method} {path} HTTP/1.1" {status} {bytes_} "-" "{ua}"')

# Normal traffic
normal_paths = ["/", "/index.html", "/about", "/contact", "/api/v1/users", "/static/main.css"]
for i in range(200):
    offset = random.randint(0, 86400)
    path   = random.choice(normal_paths)
    status = random.choice([200, 200, 200, 304, 404])
    ip     = f"10.10.{random.randint(1,5)}.{random.randint(1,254)}"
    web_lines.append(web_line(offset, ip, "GET", path, status))

# Web scanning from single IP (enumeration)
scanner_ip = "45.142.212.100"
scan_paths = [
    "/admin", "/wp-admin", "/wp-login.php", "/.env", "/.git/config",
    "/phpmyadmin", "/cgi-bin/test.cgi", "/etc/passwd", "/admin/login",
    "/backup.sql", "/config.php.bak", "/.htaccess", "/api/admin",
    "/robots.txt", "/sitemap.xml", "/xmlrpc.php", "/wp-config.php",
    "/shell.php", "/c99.php", "/r57.php", "/manager/html",
    "/login", "/wp-content/debug.log", "/server-status", "/info.php",
    "/admin/config", "/debug", "/test.php", "/index.php.bak",
    "/backup/", "/db_backup.sql", "/.DS_Store", "/CHANGELOG.txt",
    "/readme.html", "/license.txt", "/administrator/",
    "/user/login", "/account/login", "/signin", "/auth/login",
]
for i, path in enumerate(scan_paths):
    status = random.choice([404, 403, 200, 301])
    ua = random.choice([
        "sqlmap/1.7", "Nikto/2.1.6", "nmap scripting engine",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "python-requests/2.28.0",
    ])
    web_lines.append(web_line(i * 20 + 1000, scanner_ip, "GET", path, status, ua=ua))

# SQLi attempt
sqli_ip = "91.108.4.200"
sqli_paths = [
    "/login?user=admin'--&pass=x",
    "/api/users?id=1 UNION SELECT username,password FROM users--",
    "/search?q=1' OR '1'='1",
    "/product?id=1; DROP TABLE users--",
]
for i, path in enumerate(sqli_paths):
    web_lines.append(web_line(5000 + i*10, sqli_ip, "GET", path, 500, ua="sqlmap/1.7"))

# Brute force POST login
for i in range(50):
    web_lines.append(web_line(
        10000 + i*6, "77.83.247.10", "POST", "/login", 401,
        ua="python-requests/2.28.0"
    ))

# High volume spike from one IP (DoS-like)
for i in range(300):
    web_lines.append(web_line(
        20000 + i, "198.211.30.50", "GET", "/api/v1/products", 200,
        ua="curl/7.85.0"
    ))

web_lines.sort(key=lambda x: x[0])
with open("sample_logs/access.log", "w") as fh:
    for _, line in web_lines:
        fh.write(line + "\n")

print(f"✓ sample_logs/access.log ({len(web_lines)} lines)")


# ── events.json (custom JSON log) ────────────────────────────────────────────
json_events = []

def jts(offset):
    return (BASE_TS + timedelta(seconds=offset)).isoformat() + "Z"

# Normal user events
users = ["alice", "bob", "charlie"]
for i in range(30):
    json_events.append({
        "timestamp": jts(random.randint(32400, 64800)),
        "user": random.choice(users),
        "action": random.choice(["login", "file_access", "api_call", "logout"]),
        "status": "success",
        "source_ip": f"10.10.1.{random.randint(10, 50)}",
        "resource": f"/data/project_{random.randint(1,5)}/file_{random.randint(1,100)}.csv",
    })

# Suspicious events
json_events.append({
    "timestamp": jts(3*3600),
    "user": "alice",
    "action": "login",
    "status": "success",
    "source_ip": "195.26.8.100",   # new IP for alice
    "resource": "/admin/dashboard",
})

for i in range(8):
    json_events.append({
        "timestamp": jts(3*3600 + i*60),
        "user": "alice",
        "action": "data_export",
        "status": "success",
        "source_ip": "195.26.8.100",
        "resource": f"/data/sensitive/payroll_{i}.xlsx",
        "bytes_transferred": random.randint(500000, 2000000),
    })

# Failed logins
for i in range(15):
    json_events.append({
        "timestamp": jts(1000 + i*30),
        "user": "admin",
        "action": "login",
        "status": "failure",
        "source_ip": "103.99.0.100",
        "reason": "bad_password",
    })

json_events.sort(key=lambda x: x["timestamp"])
with open("sample_logs/events.json", "w") as fh:
    json.dump(json_events, fh, indent=2)

print(f"✓ sample_logs/events.json ({len(json_events)} events)")
print("\nRun: python cli.py sample_logs/auth.log sample_logs/access.log sample_logs/events.json")
