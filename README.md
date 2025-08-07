# 🛡️ Naxsi WAF Attack Testing Suite

A comprehensive script for penetration testing and validation of Naxsi WAF (Web Application Firewall) configurations.

## 📋 Description

This project contains a comprehensive bash script that executes more than **200 different types of attacks** against web applications protected by Naxsi WAF. Each attack is mapped to specific Naxsi rule IDs, allowing precise validation of security configurations.

## ✨ Features

- **200+ Attack Vectors**: Complete coverage of web vulnerabilities
- **Rule Mapping**: Each attack corresponds to specific Naxsi IDs
- **Organized Categorization**: Attacks grouped by vulnerability type
- **Detailed Reports**: Status codes and identification of triggered rules
- **Easy Configuration**: Just change the target URL in the script

## 🎯 Attack Categories

### 🔒 Naxsi Specific Rules (ID: 1-20)
- Malformed requests and parsing
- Invalid encoding and null bytes
- Unknown Content-Types
- Malformed JSON/XML
- libinjection SQL/XSS
- Malformed UTF-8

### 🔧 Additional Naxsi Rules (ID: 1000-2800)
- **SQL Injection** (1000-1015): Tautologies, UNION, comments, etc.
- **RFI** (1100-1109): HTTP, HTTPS, FTP, PHP, file protocols
- **Directory Traversal** (1200-1204): Path traversal, /etc/passwd, cmd.exe
- **XSS** (1300-1315): Event handlers, script tags, CSS expressions
- **Encoding/Evasion** (1400-1402): URL encoding, double encoding
- **File Upload** (1500-1503): Malicious extensions (.php, .jsp, .asp)
- **Command Injection** (1600-1605): cat, ls, wget, curl, nc, bash
- **Protocol Handlers** (1700-1702): javascript:, vbscript:, data:
- **Server-Side Includes** (1800-1802): exec, include, echo
- **LDAP Injection** (1900-1904): Wildcards, logical operators
- **HTTP Parameter Pollution** (2000-2001)
- **HTTP Method Override** (2100-2101)
- **Content-Type Confusion** (2200-2201)
- **Unicode Attacks** (2300-2301)
- **Double Encoding** (2400-2401)
- **Null Byte Attacks** (2500-2501)
- **CRLF Injection** (2600-2601)
- **Format String** (2700-2702)
- **Buffer Overflow** (2800-2801)

### 🔥 Advanced Attacks
- **XSS** (20+ variations): Script tags, event handlers, CSS, etc.
- **SQL Injection** (14 techniques): Boolean, time-based, error-based, etc.
- **NoSQL Injection** (6 types): MongoDB, CouchDB, Redis
- **Command Injection** (9 methods): Pipes, subshells, operators
- **LDAP Injection** (4 techniques): Wildcards, tautologies
- **LFI/Path Traversal** (8 variations): PHP wrappers, encoding
- **SSTI** (7 engines): Jinja2, Twig, Smarty, Freemarker
- **SSRF** (7 protocols): HTTP, file, gopher, dict
- **XXE** (4 techniques): File read, parameter entity, billion laughs
- **File Upload** (5 methods): Shells, double extension, null byte
- **Header Injection** (4 types): CRLF, response splitting, XSS
- **Authentication Bypass** (3 methods): SQL, NoSQL, LDAP
- **Deserialization** (3 languages): Java, PHP, Python
- **Log4Shell/JNDI** (5 variations): LDAP, RMI, DNS, obfuscated
- **HTTP Request Smuggling** (2 techniques): CL.TE, TE.CL
- **Race Conditions** (10 concurrent)
- **Prototype Pollution** (2 methods)
- **GraphQL Injection** (2 types)
- **Miscellaneous Attacks** (8 variations)

## 🚀 Usage

### 1. Configuration
```bash
# Clone the repository
git clone https://github.com/HerbertJulio/tools-work.git
cd tools-work

# Make the script executable
chmod +x naxsi_full_attacks.sh
```

### 2. Configure Target URL
Edit the `naxsi_full_attacks.sh` file and change the `TARGET_URL` variable:

```bash
TARGET_URL="https://your-protected-site.com"
```

### 3. Run Tests
```bash
./naxsi_full_attacks.sh
```

### 4. Analyze Results
The script will display:
- Attack name and Naxsi rule ID
- Payload used
- Status code of the response

Example output:
```
⚔️ [ID:1302 - XSS script tag]
Payload: field=<script>alert('xss')</script>
→ Status: 403

⚔️ [ID:1000 - SQLi tautology]
Payload: field=1' OR '1'='1
→ Status: 403
```

## 📊 Result Interpretation

- **Status 403**: WAF blocked the attack ✅
- **Status 200**: Attack passed through WAF ⚠️
- **Status 500**: Internal error (possible bypass) ⚠️
- **Status 404**: Endpoint not found
- **Other codes**: Check configuration

## 🔧 Customization

### Modify Parameters
By default, attacks use the `field` parameter. To change:

```bash
# Replace "field" with another parameter
sed -i 's/field=/username=/g' naxsi_full_attacks.sh
```

### Add Custom Headers
```bash
# Example: add authentication
attack "Custom Attack" "payload" "POST" "" "Authorization: Bearer token123"
```

### Filter Specific Attacks
```bash
# Run only XSS attacks
grep -A1 "XSS" naxsi_full_attacks.sh | bash
```

## 📈 Statistics

- **Total Attacks**: 200+
- **Naxsi Rules Covered**: 1-2801
- **Categories**: 25+
- **Protocols Tested**: HTTP, HTTPS, FTP, PHP, File, Data, etc.
- **Template Languages**: Jinja2, Twig, Smarty, Freemarker, Velocity
- **Databases**: MySQL, PostgreSQL, Oracle, MSSQL, MongoDB, Redis

## ⚠️ Legal Notice

This script is intended **EXCLUSIVELY** for:
- Authorized penetration testing
- Validation of your own WAF configurations
- Development and testing environments
- Cybersecurity research

**DO NOT USE** against systems without explicit authorization. Inadequate use may violate local and international laws.

## 🤝 Contributions

Contributions are welcome! To contribute:

1. Fork the project
2. Create a branch for your feature (`git checkout -b feature/new-rule`)
3. Commit your changes (`git commit -m 'Add new Naxsi rule'`)
4. Push to the branch (`git push origin feature/new-rule`)
5. Open a Pull Request

## 📝 Changelog

### v2.0.0 (2025-01-05)
- ✅ Added 60+ new Naxsi rules (ID: 1004-2801)
- ✅ Complete mapping of Naxsi rule IDs
- ✅ Improved categorization
- ✅ Support for Unicode and double encoding
- ✅ Buffer overflow and format string attacks

### v1.0.0 (2025-01-04)
- ✅ Initial script with 100+ attacks
- ✅ Basic Naxsi rules (ID: 1-20)
- ✅ Main vulnerability categories
- ✅ Standardized attack function

## 📚 References

- [Naxsi Documentation](https://github.com/nbs-system/naxsi)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 📧 Contact

- **Author**: Herbert Julio
- **GitHub**: [@HerbertJulio](https://github.com/HerbertJulio)
- **Project**: [tools-work](https://github.com/HerbertJulio/tools-work)

---

**⭐ If this project was helpful, consider giving a star on GitHub!**