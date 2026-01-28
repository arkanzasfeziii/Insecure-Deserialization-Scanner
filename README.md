# 🔍 Insecure Deserialization Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org/)
[![Security Tool](https://img.shields.io/badge/Security-Vulnerability_Scanner-red)](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)

> ⚠️ **Ethical Use Only**: This tool is designed for **authorized security testing**. Never scan systems without explicit written permission. Unauthorized scanning may violate computer crime laws.

Advanced automated vulnerability detection tool that identifies insecure deserialization vulnerabilities across 7+ programming languages and frameworks.

## ✨ Key Features
- 🔎 **Multi-Language Support**: Python, Java, PHP, .NET, Ruby, Node.js, XML
- 📁 **Static Analysis**: Source code scanning for dangerous patterns
- 🌐 **Dynamic Testing**: Live vulnerability detection against web applications/APIs
- 💾 **Serialized File Analysis**: Inspect `.pkl`, `.ser`, `.yaml` files for malicious payloads
- 📡 **Network Traffic Analysis**: PCAP inspection for serialized data in transit
- 🚨 **Gadget Chain Detection**: Identify known exploit chains (Commons Collections, Fastjson, etc.)
- 📊 **Professional Reporting**: HTML, JSON, and console reports with fix recommendations
- 👶 **Easy Mode**: Beginner-friendly interactive interface

## 🛡️ Vulnerabilities Detected
| Language | Vulnerable Functions/Patterns | Severity |
|----------|-------------------------------|----------|
| **Python** | `pickle.loads()`, `yaml.load()`, `marshal.loads()` | 🔴 Critical |
| **Java** | `ObjectInputStream`, `XMLDecoder`, Fastjson AutoType | 🔴 Critical |
| **PHP** | `unserialize()`, PHAR deserialization | 🔴 Critical |
| **.NET** | `BinaryFormatter`, `NetDataContractSerializer` | 🔴 Critical |
| **Ruby** | `Marshal.load()`, unsafe `YAML.load()` | 🔴 Critical |
| **Node.js** | Prototype pollution, `node-serialize` | 🟠 High |
| **XML** | XXE vulnerabilities, unsafe parsers | 🟠 High |

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/insecure-deserialization-scanner.git
cd insecure-deserialization-scanner
```
Install dependencies
```pip install -r requirements.txt```
Optional: Install full dependencies for all features
```pip install requests termcolor pyyaml scapy```

#Basic Usage
Interactive easy mode (recommended for beginners)
```python scanner.py --easy```
Scan source code directory
```python scanner.py --target /path/to/project --mode static```
Test live web application
```python scanner.py --target https://example.com/api --mode dynamic```
Analyze suspicious serialized file
```python scanner.py --target malicious.pkl --mode full```
Generate HTML report
```python scanner.py --target /path/to/code --output-html report.html```

📋 Example Output
✅ Static analysis complete. Found 3 issues.

══════════════════════════════════════════════════════════════════════

⚠️  INSECURE DESERIALIZATION VULNERABILITIES DETECTED

══════════════════════════════════════════════════════════════════════

Total Issues Found: 3
  🔴 CRITICAL: 2
  🟠 HIGH: 1

[1] 🔴 CRITICAL - Unsafe pickle deserialization detected
    📁 File: app/utils.py
    📍 Line: 42
    💻 Language: PYTHON
    🔍 Reference: CWE-502: Deserialization of Untrusted Data
    ❌ Vulnerable Code:
       data = pickle.loads(request.data)
    ✅ Fix Recommendation:
       Avoid pickle for untrusted data. Use JSON or implement whitelist validation.

[2] 🔴 CRITICAL - Unsafe YAML deserialization (use safe_load)
    📁 File: config/loader.py
    📍 Line: 17
    💻 Language: PYTHON
    🔍 Reference: CWE-502: Deserialization of Untrusted Data
    ❌ Vulnerable Code:
       config = yaml.load(user_input)
    ✅ Fix Recommendation:
       Use yaml.safe_load() instead of yaml.load()

[3] 🟠 HIGH - Shelve uses pickle internally - unsafe for untrusted data
    📁 File: cache/manager.py
    📍 Line: 88
    💻 Language: PYTHON
    🔍 Reference: CWE-502: Deserialization of Untrusted Data
    ✅ Fix Recommendation:
       Validate file source or use SQLite instead.

#📂 Supported Formats & Signatures
Format     ,File Extensions                       ,Magic Bytes
Python      Pickle,.pkl",".pickle,                \x80\x03", "\x80\x04
Java        Serialized,.ser",".serialized,        \xac\xed\x00\x05
PHP         Serialized,.php,                      O:", "a:
.NET        BinaryFormatter,.dat,                 AAEAAAD (Base64)
YAML        (unsafe),.yaml", ".yml,               !!python/object

#⚙️ Advanced Usage
Full scan with all detection methods
```python scanner.py --target /path/to/app --mode full --verbose```
Scan specific language only
```python scanner.py --target src/ --type python --mode static```
Test with custom HTTP method
```python scanner.py --target https://api.example.com --method GET --mode dynamic```
Generate both JSON and HTML reports
```python scanner.py --target project/ --output-json report.json --output-html report.html```

#📜 Requirements
Core dependencies
requests>=2.28.0
termcolor>=2.0.0
pyyaml>=6.0

Optional (for PCAP analysis)
scapy>=2.4.5

Python 3.7+

#⚠️ Legal Disclaimer
This tool is provided strictly for authorized security testing purposes. The authors assume no liability for misuse. You are solely responsible for ensuring you have explicit written permission before scanning any system. Unauthorized scanning may violate:
Computer Fraud and Abuse Act (CFAA)
GDPR Article 32 (security testing without consent)
Local computer crime laws in your jurisdiction
Never use this tool against systems you do not own or have explicit written authorization to test.

#🌐 References
OWASP: Deserialization of Untrusted Data
CWE-502: Deserialization of Untrusted Data
PHP Object Injection
.NET BinaryFormatter Security Guide
