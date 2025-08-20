# 🐍 Open_Cobra – Advanced Cybersecurity Toolkit

![Open_Cobra logo](./logo.png)

## 📌 Overview

**Open_Cobra** is a **multi-tool Python-based cybersecurity framework** designed for penetration testers, bug bounty hunters, and security researchers.
It combines **multiple modules** into a single toolkit:

1. **Passive Recon** – Generates advanced Google Dork queries (80+ combinations)
2. **Vulnerability Checker** – Localhost-oriented basic scanning for PHP/ASP/JS-based issues
3. **Hash Cracker** – Dictionary & brute force hash cracking (MD5, SHA1, SHA256)
4. **Prompt Injection Tester** – Lists AI prompt injection payloads by scenario
5. **Sample Report Generator** – Generates a professional security assessment report based on your recon & scan data

---

## 🚀 Features

- **Passive Recon**
  - 10+ dork categories: Sensitive Files, Directory Listings, Login Pages, Database Dumps, API Keys, Error Messages, Advanced Combinations, Power Combos, and more.
  - Over **80 unique Google Dork queries** for deep surface web discovery.

- **Local Vulnerability Scanner**
  - Detects basic misconfigurations & exposed files on local PHP/ASP servers.
  - Checks for dangerous file extensions, error messages, and default admin panels.

- **Hash Cracker**
  - Supports MD5, SHA1, SHA256.
  - Dictionary mode (uses `data_wordlist.txt`) and small brute force mode.

- **Prompt Injection Tester**
  - Categorized list of prompt injection payloads for LLM security testing.
  - Scenarios include Data Exfiltration, Jailbreak, Role Override, and Stealth Bypass.

- **Report Generator**
  - Produces a **realistic pentest-style report** with:
    - Recon results
    - Vulnerabilities found
    - Cracked hashes
    - Prompt injection scenarios tested
    - Severity assessment & recommendations

---

## 📂 Project Structure
 - open_cobra/
   - │
   - ├── recon.py                  # Main tool
   - ├── data_wordlist.txt         # Wordlist for hash cracking
   - ├── reports/                  # Generated reports
   - └── README.md                 # Documentation
---

## 🔧 Installation

1. **Clone the repository**
 - git clone https://github.com/Ricky-Hacker001/open_cobra.git
 - cd open_cobra

2. **Install dependencies**
 - pip install -r requirements.txt
3. **Download a good wordlist (optional)**
 - https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases

 - mv rockyou.txt data_wordlist.txt

---

## 🖥️ Usage
 - Run the toolkit:
 - python3 recon.py
 - Choose a module:
  - [1] Passive Recon (generate Google dorks)
  - [2] Vulnerability Checker (LOCALHOST ONLY)
  - [3] Hash Cracker
  - [4] Prompt Injection Tester
  - [5] Generate Security Report
  - [6] Exit
